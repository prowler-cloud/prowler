from typing import Optional

from botocore.client import ClientError
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


################## DynamoDB
class DynamoDB(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.tables = []
        self.__threading_call__(self.__list_tables__)
        self.__describe_table__()
        self.__describe_continuous_backups__()
        self.__list_tags_for_resource__()

    def __list_tables__(self, regional_client):
        logger.info("DynamoDB - Listing tables...")
        try:
            list_tables_paginator = regional_client.get_paginator("list_tables")
            for page in list_tables_paginator.paginate():
                for table in page["TableNames"]:
                    arn = f"arn:{self.audited_partition}:dynamodb:{regional_client.region}:{self.audited_account}:table/{table}"
                    if not self.audit_resources or (
                        is_resource_filtered(arn, self.audit_resources)
                    ):
                        self.tables.append(
                            Table(
                                arn=arn,
                                name=table,
                                encryption_type=None,
                                kms_arn=None,
                                region=regional_client.region,
                            )
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __describe_table__(self):
        logger.info("DynamoDB - Describing Table...")
        try:
            for table in self.tables:
                regional_client = self.regional_clients[table.region]
                properties = regional_client.describe_table(TableName=table.name)[
                    "Table"
                ]
                if "SSEDescription" in properties:
                    if "SSEType" in properties["SSEDescription"]:
                        table.encryption_type = properties["SSEDescription"]["SSEType"]
                if table.encryption_type == "KMS":
                    table.kms_arn = properties["SSEDescription"]["KMSMasterKeyArn"]
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
            )

    def __describe_continuous_backups__(self):
        logger.info("DynamoDB - Describing Continuous Backups...")
        try:
            for table in self.tables:
                try:
                    regional_client = self.regional_clients[table.region]
                    properties = regional_client.describe_continuous_backups(
                        TableName=table.name
                    )["ContinuousBackupsDescription"]
                    if "PointInTimeRecoveryDescription" in properties:
                        if (
                            properties["PointInTimeRecoveryDescription"][
                                "PointInTimeRecoveryStatus"
                            ]
                            == "ENABLED"
                        ):
                            table.pitr = True
                except ClientError as error:
                    if error.response["Error"]["Code"] == "TableNotFoundException":
                        logger.warning(
                            f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                        )
                    else:
                        logger.error(
                            f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                        )
                    continue
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
            )

    def __list_tags_for_resource__(self):
        logger.info("DynamoDB - List Tags...")
        try:
            for table in self.tables:
                try:
                    regional_client = self.regional_clients[table.region]
                    response = regional_client.list_tags_of_resource(
                        ResourceArn=table.arn
                    )["Tags"]
                    table.tags = response
                except ClientError as error:
                    if error.response["Error"]["Code"] == "ResourceNotFoundException":
                        logger.warning(
                            f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                        )
                    else:
                        logger.error(
                            f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                        )
                    continue
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


################## DynamoDB DAX
class DAX(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.clusters = []
        self.__threading_call__(self.__describe_clusters__)
        self.__list_tags_for_resource__()

    def __describe_clusters__(self, regional_client):
        logger.info("DynamoDB DAX - Describing clusters...")
        try:
            describe_clusters_paginator = regional_client.get_paginator(
                "describe_clusters"
            )
            for page in describe_clusters_paginator.paginate():
                for cluster in page["Clusters"]:
                    if not self.audit_resources or (
                        is_resource_filtered(
                            cluster["ClusterArn"], self.audit_resources
                        )
                    ):
                        encryption = False
                        if "SSEDescription" in cluster:
                            if cluster["SSEDescription"]["Status"] == "ENABLED":
                                encryption = True
                        self.clusters.append(
                            Cluster(
                                arn=cluster["ClusterArn"],
                                name=cluster["ClusterName"],
                                encryption=encryption,
                                region=regional_client.region,
                            )
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __list_tags_for_resource__(self):
        logger.info("DAX - List Tags...")
        for cluster in self.clusters:
            try:
                regional_client = self.regional_clients[cluster.region]
                # In the DAX service to call list_tags we need to pass the cluster ARN as the resource name
                response = regional_client.list_tags(ResourceName=cluster.arn)["Tags"]
                cluster.tags = response

            except ClientError as error:
                if error.response["Error"]["Code"] == "InvalidARNFault":
                    logger.warning(
                        f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
                    continue

            except Exception as error:
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )


class Table(BaseModel):
    arn: str
    name: str
    encryption_type: Optional[str]
    kms_arn: Optional[str]
    pitr: bool = False
    region: str
    tags: Optional[list] = []


class Cluster(BaseModel):
    arn: str
    name: str
    encryption: bool
    region: str
    tags: Optional[list] = []
