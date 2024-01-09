from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


################## Athena
class Athena(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.workgroups = {}
        self.__threading_call__(self.__list_workgroups__)
        self.__get_workgroups__()
        self.__list_query_executions__()
        self.__list_tags_for_resource__()

    def __list_workgroups__(self, regional_client):
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

    def __get_workgroups__(self):
        logger.info("Athena - Getting WorkGroups...")
        try:
            for workgroup in self.workgroups.values():
                try:
                    wg = self.regional_clients[workgroup.region].get_work_group(
                        WorkGroup=workgroup.name
                    )

                    wg_configuration = wg.get("WorkGroup").get("Configuration")
                    self.workgroups[
                        workgroup.arn
                    ].enforce_workgroup_configuration = wg_configuration.get(
                        "EnforceWorkGroupConfiguration", False
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
                        self.workgroups[
                            workgroup.arn
                        ].encryption_configuration = encryption_configuration
                except Exception as error:
                    logger.error(
                        f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )

        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __list_query_executions__(self):
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

    def __list_tags_for_resource__(self):
        logger.info("Athena - Listing Tags...")
        try:
            for workgroup in self.workgroups.values():
                try:
                    regional_client = self.regional_clients[workgroup.region]
                    workgroup.tags = regional_client.list_tags_for_resource(
                        ResourceARN=workgroup.arn
                    )["Tags"]
                except Exception as error:
                    logger.error(
                        f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
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
    tags: Optional[list] = []
