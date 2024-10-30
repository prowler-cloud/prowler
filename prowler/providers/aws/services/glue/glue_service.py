import json
from typing import Dict, List, Optional

from botocore.exceptions import ClientError
from pydantic import BaseModel, Field

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class Glue(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.connections = []
        self.__threading_call__(self._get_connections)
        self.__threading_call__(self._list_tags, self.connections)
        self.tables = []
        self.__threading_call__(self._search_tables)
        self.data_catalogs = {}
        self.__threading_call__(self._get_data_catalogs)
        self.__threading_call__(self._get_resource_policy, self.data_catalogs.values())
        self.dev_endpoints = []
        self.__threading_call__(self._get_dev_endpoints)
        self.__threading_call__(self._list_tags, self.dev_endpoints)
        self.security_configs = []
        self.__threading_call__(self._get_security_configurations)
        self.jobs = []
        self.__threading_call__(self._get_jobs)
        self.__threading_call__(self._list_tags, self.jobs)
        self.ml_transforms = {}
        self.__threading_call__(self._get_ml_transforms)
        self.__threading_call__(self._list_tags, self.ml_transforms.values())

    def _get_data_catalog_arn_template(self, region):
        return f"arn:{self.audited_partition}:glue:{region}:{self.audited_account}:data-catalog"

    def _get_connections(self, regional_client):
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
                                name=conn.get("Name", ""),
                                type=conn.get("ConnectionType", ""),
                                properties=conn.get("ConnectionProperties", {}),
                                region=regional_client.region,
                            )
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_dev_endpoints(self, regional_client):
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
        except ClientError as error:
            # Check if the operation is not supported in the region
            if error.response["Error"]["Message"].startswith(
                "Operation is not supported"
            ):
                logger.warning(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            else:
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_jobs(self, regional_client):
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
                                arguments=job.get("DefaultArguments", {}),
                                region=regional_client.region,
                            )
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_security_configurations(self, regional_client):
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

    def _search_tables(self, regional_client):
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

    def _get_data_catalogs(self, regional_client):
        logger.info("Glue - Catalog ...")
        try:
            settings = regional_client.get_data_catalog_encryption_settings()[
                "DataCatalogEncryptionSettings"
            ]
            tables_in_region = False
            for table in self.tables:
                if table.region == regional_client.region:
                    tables_in_region = True
            catalog_encryption_settings = CatalogEncryptionSetting(
                mode=settings["EncryptionAtRest"]["CatalogEncryptionMode"],
                kms_id=settings["EncryptionAtRest"].get("SseAwsKmsKeyId"),
                password_encryption=settings["ConnectionPasswordEncryption"][
                    "ReturnConnectionPasswordEncrypted"
                ],
                password_kms_id=settings["ConnectionPasswordEncryption"].get(
                    "AwsKmsKeyId"
                ),
            )
            self.data_catalogs[regional_client.region] = DataCatalog(
                tables=tables_in_region,
                region=regional_client.region,
                encryption_settings=catalog_encryption_settings,
            )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_tags(self, resource: any):
        try:
            resource.tags = [
                self.regional_clients[resource.region].get_tags(
                    ResourceArn=resource.arn
                )["Tags"]
            ]
        except Exception as error:
            logger.error(
                f"{resource.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_ml_transforms(self, regional_client):
        logger.info("Glue - Getting ML Transforms...")
        try:
            transforms = regional_client.get_ml_transforms()["Transforms"]
            for transform in transforms:
                ml_transform_arn = f"arn:{self.audited_partition}:glue:{regional_client.region}:{self.audited_account}:mlTransform/{transform['TransformId']}"
                if not self.audit_resources or is_resource_filtered(
                    ml_transform_arn, self.audit_resources
                ):
                    self.ml_transforms[ml_transform_arn] = MLTransform(
                        arn=ml_transform_arn,
                        id=transform["TransformId"],
                        name=transform["Name"],
                        user_data_encryption=transform.get("TransformEncryption", {})
                        .get("MlUserDataEncryption", {})
                        .get("MlUserDataEncryptionMode", "DISABLED"),
                        region=regional_client.region,
                    )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_resource_policy(self, data_catalog):
        logger.info("Glue - Getting Resource Policy...")
        try:
            data_catalog_policy = self.regional_clients[
                data_catalog.region
            ].get_resource_policy()
            data_catalog.policy = json.loads(data_catalog_policy["PolicyInJson"])
        except ClientError as error:
            if error.response["Error"]["Code"] == "EntityNotFoundException":
                logger.warning(
                    f"{data_catalog.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            else:
                logger.error(
                    f"{data_catalog.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        except Exception as error:
            logger.error(
                f"{data_catalog.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Connection(BaseModel):
    name: str
    arn: str
    type: str
    properties: dict
    region: str
    tags: Optional[List[Dict[str, str]]] = Field(default_factory=list)


class Table(BaseModel):
    name: str
    arn: str
    database: str
    catalog: Optional[str]
    region: str
    tags: Optional[List[Dict[str, str]]] = Field(default_factory=list)


class CatalogEncryptionSetting(BaseModel):
    mode: str
    kms_id: Optional[str]
    password_encryption: bool
    password_kms_id: Optional[str]


class DevEndpoint(BaseModel):
    name: str
    arn: str
    security: Optional[str]
    region: str
    tags: Optional[List[Dict[str, str]]] = Field(default_factory=list)


class Job(BaseModel):
    arn: str
    name: str
    security: Optional[str]
    arguments: Optional[Dict[str, str]] = Field(default_factory=dict)
    region: str
    tags: Optional[List[Dict[str, str]]] = Field(default_factory=list)


class SecurityConfig(BaseModel):
    name: str
    s3_encryption: str
    s3_key_arn: Optional[str]
    cw_encryption: str
    cw_key_arn: Optional[str]
    jb_encryption: str
    jb_key_arn: Optional[str]
    region: str
    tags: Optional[List[Dict[str, str]]] = Field(default_factory=list)


class MLTransform(BaseModel):
    arn: str
    id: str
    name: str
    user_data_encryption: str
    region: str
    tags: Optional[List[Dict[str, str]]] = Field(default_factory=list)


class DataCatalog(BaseModel):
    tables: bool
    region: str
    encryption_settings: Optional[CatalogEncryptionSetting]
    policy: Optional[dict]
    tags: Optional[List[Dict[str, str]]] = Field(default_factory=list)
