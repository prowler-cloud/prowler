from typing import Optional

from pydantic import BaseModel, Field

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class Athena(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.workgroups = {}
        self.__threading_call__(self._list_workgroups)
        self.__threading_call__(self._get_workgroups, self.workgroups.values())
        self._list_query_executions()
        self._list_tags_for_resource()

    def _list_workgroups(self, regional_client):
        logger.info("Athena - Listing WorkGroups...")
        try:
            list_workgroups = regional_client.list_work_groups()
            for workgroup in list_workgroups["WorkGroups"]:
                try:
                    workgroup_name = workgroup["Name"]
                    workgroup_arn = f"arn:{self.audited_partition}:athena:{regional_client.region}:{self.audited_account}:workgroup/{workgroup_name}"
                    if not self.audit_resources or (
                        is_resource_filtered(workgroup_arn, self.audit_resources)
                    ):
                        self.workgroups[workgroup_arn] = WorkGroup(
                            arn=workgroup_arn,
                            name=workgroup_name,
                            state=workgroup["State"],
                            region=regional_client.region,
                        )
                except Exception as error:
                    logger.error(
                        f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_workgroups(self, workgroup):
        logger.info("Athena - Getting WorkGroups...")
        try:
            wg = self.regional_clients[workgroup.region].get_work_group(
                WorkGroup=workgroup.name
            )

            wg_configuration = wg.get("WorkGroup").get("Configuration")
            self.workgroups[workgroup.arn].enforce_workgroup_configuration = (
                wg_configuration.get("EnforceWorkGroupConfiguration", False)
            )

            # We include an empty EncryptionConfiguration to handle if the workgroup does not have encryption configured
            encryption = (
                wg_configuration.get(
                    "ResultConfiguration",
                    {"EncryptionConfiguration": {}},
                )
                .get(
                    "EncryptionConfiguration",
                    {"EncryptionOption": ""},
                )
                .get("EncryptionOption")
            )

            if encryption in ["SSE_S3", "SSE_KMS", "CSE_KMS"]:
                encryption_configuration = EncryptionConfiguration(
                    encryption_option=encryption, encrypted=True
                )
                self.workgroups[workgroup.arn].encryption_configuration = (
                    encryption_configuration
                )

            workgroup.cloudwatch_logging = wg_configuration.get(
                "PublishCloudWatchMetricsEnabled", False
            )
        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_query_executions(self):
        logger.info("Athena - Listing Queries...")
        try:
            for workgroup in self.workgroups.values():
                try:
                    queries = (
                        self.regional_clients[workgroup.region]
                        .list_query_executions(WorkGroup=workgroup.name)
                        .get("QueryExecutionIds", [])
                    )
                    if queries:
                        workgroup.queries = True
                except Exception as error:
                    logger.error(
                        f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_tags_for_resource(self):
        logger.info("Athena - Listing Tags...")
        try:
            for workgroup in self.workgroups.values():
                try:
                    regional_client = self.regional_clients[workgroup.region]
                    workgroup.tags = regional_client.list_tags_for_resource(
                        ResourceARN=workgroup.arn
                    ).get("Tags", [])
                except Exception as error:
                    logger.error(
                        f"{workgroup.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class EncryptionConfiguration(BaseModel):
    encryption_option: str
    encrypted: bool


class WorkGroup(BaseModel):
    arn: str
    name: str
    state: str
    encryption_configuration: EncryptionConfiguration = EncryptionConfiguration(
        encryption_option="", encrypted=False
    )
    enforce_workgroup_configuration: bool = False
    queries: bool = False
    region: str
    cloudwatch_logging: bool = False
    tags: Optional[list] = Field(default_factory=list)
