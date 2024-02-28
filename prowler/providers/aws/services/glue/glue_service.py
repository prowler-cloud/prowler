from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


################## Glue
class Glue(AWSService):
    def __init__(self, audit_info):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, audit_info)
        self.data_catalog_arn_template = f"arn:{self.audited_partition}:glue:{self.region}:{self.audited_account}:data-catalog"
        self.connections = []
        self.__threading_call__(self.__get_connections__)
        self.tables = []
        self.__threading_call__(self.__search_tables__)
        self.catalog_encryption_settings = []
        self.__threading_call__(self.__get_data_catalog_encryption_settings__)
        self.dev_endpoints = []
        self.__threading_call__(self.__get_dev_endpoints__)
        self.security_configs = []
        self.__threading_call__(self.__get_security_configurations__)
        self.jobs = []
        self.__threading_call__(self.__get_jobs__)

    def __get_connections__(self, regional_client):
        logger.info("Glue - Getting connections...")
        try:
            get_connections_paginator = regional_client.get_paginator("get_connections")
            for page in get_connections_paginator.paginate():
                for conn in page["ConnectionList"]:
                    arn = f"arn:{self.audited_partition}:glue:{regional_client.region}:{self.audited_account}:connection/{conn['Name']}"
                    if not self.audit_resources or (
                        is_resource_filtered(arn, self.audit_resources)
                    ):
                        self.connections.append(
                            Connection(
                                arn=arn,
                                name=conn["Name"],
                                type=conn["ConnectionType"],
                                properties=conn["ConnectionProperties"],
                                region=regional_client.region,
                            )
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __get_dev_endpoints__(self, regional_client):
        logger.info("Glue - Getting dev endpoints...")
        try:
            get_dev_endpoints_paginator = regional_client.get_paginator(
                "get_dev_endpoints"
            )
            for page in get_dev_endpoints_paginator.paginate():
                for endpoint in page["DevEndpoints"]:
                    arn = f"arn:{self.audited_partition}:glue:{regional_client.region}:{self.audited_account}:devEndpoint/{endpoint['EndpointName']}"
                    if not self.audit_resources or (
                        is_resource_filtered(arn, self.audit_resources)
                    ):
                        self.dev_endpoints.append(
                            DevEndpoint(
                                arn=arn,
                                name=endpoint["EndpointName"],
                                security=endpoint.get("SecurityConfiguration"),
                                region=regional_client.region,
                            )
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __get_jobs__(self, regional_client):
        logger.info("Glue - Getting jobs...")
        try:
            get_jobs_paginator = regional_client.get_paginator("get_jobs")
            for page in get_jobs_paginator.paginate():
                for job in page["Jobs"]:
                    arn = f"arn:{self.audited_partition}:glue:{regional_client.region}:{self.audited_account}:job/{job['Name']}"
                    if not self.audit_resources or (
                        is_resource_filtered(arn, self.audit_resources)
                    ):
                        self.jobs.append(
                            Job(
                                name=job["Name"],
                                arn=arn,
                                security=job.get("SecurityConfiguration"),
                                arguments=job.get("DefaultArguments"),
                                region=regional_client.region,
                            )
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __get_security_configurations__(self, regional_client):
        logger.info("Glue - Getting security configs...")
        try:
            get_security_configurations_paginator = regional_client.get_paginator(
                "get_security_configurations"
            )
            for page in get_security_configurations_paginator.paginate():
                for config in page["SecurityConfigurations"]:
                    if not self.audit_resources or (
                        is_resource_filtered(config["Name"], self.audit_resources)
                    ):
                        self.security_configs.append(
                            SecurityConfig(
                                name=config["Name"],
                                s3_encryption=config["EncryptionConfiguration"][
                                    "S3Encryption"
                                ][0]["S3EncryptionMode"],
                                s3_key_arn=config["EncryptionConfiguration"][
                                    "S3Encryption"
                                ][0].get("KmsKeyArn"),
                                cw_encryption=config["EncryptionConfiguration"][
                                    "CloudWatchEncryption"
                                ]["CloudWatchEncryptionMode"],
                                cw_key_arn=config["EncryptionConfiguration"][
                                    "CloudWatchEncryption"
                                ].get("KmsKeyArn"),
                                jb_encryption=config["EncryptionConfiguration"][
                                    "JobBookmarksEncryption"
                                ]["JobBookmarksEncryptionMode"],
                                jb_key_arn=config["EncryptionConfiguration"][
                                    "JobBookmarksEncryption"
                                ].get("KmsKeyArn"),
                                region=regional_client.region,
                            )
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __search_tables__(self, regional_client):
        logger.info("Glue - Search Tables...")
        try:
            for table in regional_client.search_tables()["TableList"]:
                arn = f"arn:{self.audited_partition}:glue:{regional_client.region}:{self.audited_account}:table/{table['DatabaseName']}/{table['Name']}"
                if not self.audit_resources or (
                    is_resource_filtered(arn, self.audit_resources)
                ):
                    self.tables.append(
                        Table(
                            arn=arn,
                            name=table["Name"],
                            database=table["DatabaseName"],
                            catalog=table["CatalogId"],
                            region=regional_client.region,
                        )
                    )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __get_data_catalog_encryption_settings__(self, regional_client):
        logger.info("Glue - Catalog Encryption Settings...")
        try:
            settings = regional_client.get_data_catalog_encryption_settings()[
                "DataCatalogEncryptionSettings"
            ]
            tables_in_region = False
            for table in self.tables:
                if table.region == regional_client.region:
                    tables_in_region = True
            self.catalog_encryption_settings.append(
                CatalogEncryptionSetting(
                    mode=settings["EncryptionAtRest"]["CatalogEncryptionMode"],
                    kms_id=settings["EncryptionAtRest"].get("SseAwsKmsKeyId"),
                    password_encryption=settings["ConnectionPasswordEncryption"][
                        "ReturnConnectionPasswordEncrypted"
                    ],
                    password_kms_id=settings["ConnectionPasswordEncryption"].get(
                        "AwsKmsKeyId"
                    ),
                    region=regional_client.region,
                    tables=tables_in_region,
                )
            )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Connection(BaseModel):
    name: str
    arn: str
    type: str
    properties: dict
    region: str


class Table(BaseModel):
    name: str
    arn: str
    database: str
    catalog: Optional[str]
    region: str


class CatalogEncryptionSetting(BaseModel):
    mode: str
    kms_id: Optional[str]
    password_encryption: bool
    password_kms_id: Optional[str]
    tables: bool
    region: str


class DevEndpoint(BaseModel):
    name: str
    arn: str
    security: Optional[str]
    region: str


class Job(BaseModel):
    arn: str
    name: str
    security: Optional[str]
    arguments: Optional[dict]
    region: str


class SecurityConfig(BaseModel):
    name: str
    s3_encryption: str
    s3_key_arn: Optional[str]
    cw_encryption: str
    cw_key_arn: Optional[str]
    jb_encryption: str
    jb_key_arn: Optional[str]
    region: str
