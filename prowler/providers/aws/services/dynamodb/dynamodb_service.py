import threading
from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.aws_provider import generate_regional_clients


################## DynamoDB
class DynamoDB:
    def __init__(self, audit_info):
        self.service = "dynamodb"
        self.session = audit_info.audit_session
        self.audited_account = audit_info.audited_account
        self.audit_resources = audit_info.audit_resources
        self.regional_clients = generate_regional_clients(self.service, audit_info)
        self.tables = []
        self.__threading_call__(self.__list_tables__)
        self.__describe_table__()
        self.__describe_continuous_backups__()
        self.__list_tags_for_resource__()

    def __get_session__(self):
        return self.session

    def __threading_call__(self, call):
        threads = []
        for regional_client in self.regional_clients.values():
            threads.append(threading.Thread(target=call, args=(regional_client,)))
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    def __list_tables__(self, regional_client):
        logger.info("DynamoDB - Listing tables...")
        try:
            list_tables_paginator = regional_client.get_paginator("list_tables")
            for page in list_tables_paginator.paginate():
                for table in page["TableNames"]:
                    if not self.audit_resources or (
                        is_resource_filtered(table, self.audit_resources)
                    ):
                        self.tables.append(
                            Table(
                                arn="",
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
                table.arn = properties["TableArn"]
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
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
            )

    def __list_tags_for_resource__(self):
        logger.info("DynamoDB - List Tags...")
        try:
            for table in self.tables:
                regional_client = self.regional_clients[table.region]
                response = regional_client.list_tags_of_resource(ResourceArn=table.arn)[
                    "Tags"
                ]
                table.tags = response
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


################## DynamoDB DAX
class DAX:
    def __init__(self, audit_info):
        self.service = "dax"
        self.session = audit_info.audit_session
        self.audited_account = audit_info.audited_account
        self.audit_resources = audit_info.audit_resources
        self.regional_clients = generate_regional_clients(self.service, audit_info)
        self.clusters = []
        self.__threading_call__(self.__describe_clusters__)
        self.__list_tags_for_resource__()

    def __get_session__(self):
        return self.session

    def __threading_call__(self, call):
        threads = []
        for regional_client in self.regional_clients.values():
            threads.append(threading.Thread(target=call, args=(regional_client,)))
        for t in threads:
            t.start()
        for t in threads:
            t.join()

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
        try:
            for cluster in self.clusters:
                regional_client = self.regional_clients[cluster.region]
                response = regional_client.list_tags(ResourceName=cluster.name)["Tags"]
                cluster.tags = response
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
