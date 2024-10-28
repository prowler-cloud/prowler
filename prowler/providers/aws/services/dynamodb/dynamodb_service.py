import json
from typing import Optional

from botocore.client import ClientError
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class DynamoDB(AWSService):
    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)
        self.tables = {}
        self.__threading_call__(self._list_tables)
        self._describe_table()
        self._describe_continuous_backups()
        self._get_resource_policy()
        self._list_tags_for_resource()

    def _list_tables(self, regional_client):
        logger.info("DynamoDB - Listing tables...")
        try:
            list_tables_paginator = regional_client.get_paginator("list_tables")
            for page in list_tables_paginator.paginate():
                for table in page["TableNames"]:
                    arn = f"arn:{self.audited_partition}:dynamodb:{regional_client.region}:{self.audited_account}:table/{table}"
                    if not self.audit_resources or (
                        is_resource_filtered(arn, self.audit_resources)
                    ):
                        self.tables[arn] = Table(
                            name=table,
                            encryption_type=None,
                            kms_arn=None,
                            region=regional_client.region,
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_table(self):
        logger.info("DynamoDB - Describing Table...")
        try:
            for table in self.tables.values():
                regional_client = self.regional_clients[table.region]
                properties = regional_client.describe_table(TableName=table.name)[
                    "Table"
                ]
                table.billing_mode = properties.get("BillingModeSummary", {}).get(
                    "BillingMode", "PROVISIONED"
                )
                if "SSEDescription" in properties:
                    if "SSEType" in properties["SSEDescription"]:
                        table.encryption_type = properties["SSEDescription"]["SSEType"]
                if table.encryption_type == "KMS":
                    table.kms_arn = properties["SSEDescription"]["KMSMasterKeyArn"]

                table.deletion_protection = properties.get(
                    "DeletionProtectionEnabled", False
                )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
            )

    def _describe_continuous_backups(self):
        logger.info("DynamoDB - Describing Continuous Backups...")
        try:
            for table in self.tables.values():
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

    def _get_resource_policy(self):
        logger.info("DynamoDB - Get Resource Policy...")
        try:
            for table_arn, table in self.tables.items():
                try:
                    regional_client = self.regional_clients[table.region]
                    response = regional_client.get_resource_policy(
                        ResourceArn=table_arn
                    )
                    table.policy = json.loads(response["Policy"])
                except ClientError as error:
                    if error.response["Error"]["Code"] == "ResourceNotFoundException":
                        logger.warning(
                            f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                        )
                    elif error.response["Error"]["Code"] == "PolicyNotFoundException":
                        logger.warning(
                            f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                        )
                    else:
                        logger.error(
                            f"{regional_client.region} -- {error.__class__.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                        )
                    continue
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_tags_for_resource(self):
        logger.info("DynamoDB - List Tags...")
        try:
            for table_arn, table in self.tables.items():
                try:
                    regional_client = self.regional_clients[table.region]
                    response = regional_client.list_tags_of_resource(
                        ResourceArn=table_arn
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


class DAX(AWSService):
    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)
        self.clusters = []
        self.__threading_call__(self._describe_clusters)
        self._list_tags_for_resource()

    def _describe_clusters(self, regional_client):
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
                        tls_encryption = False
                        if "SSEDescription" in cluster:
                            if cluster["SSEDescription"]["Status"] == "ENABLED":
                                encryption = True
                        if "ClusterEndpointEncryptionType" in cluster:
                            if cluster["ClusterEndpointEncryptionType"] == "TLS":
                                tls_encryption = True
                        self.clusters.append(
                            Cluster(
                                arn=cluster["ClusterArn"],
                                name=cluster["ClusterName"],
                                encryption=encryption,
                                node_azs=[
                                    node["AvailabilityZone"]
                                    for node in cluster.get("Nodes", {})
                                ],
                                region=regional_client.region,
                                tls_encryption=tls_encryption,
                            )
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_tags_for_resource(self):
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
    name: str
    billing_mode: str = "PROVISIONED"
    encryption_type: Optional[str]
    kms_arn: Optional[str]
    pitr: bool = False
    policy: Optional[dict] = None
    region: str
    tags: Optional[list] = []
    deletion_protection: bool = False


class Cluster(BaseModel):
    arn: str
    name: str
    encryption: bool
    node_azs: Optional[list] = []
    region: str
    tags: Optional[list] = []
    tls_encryption: bool
