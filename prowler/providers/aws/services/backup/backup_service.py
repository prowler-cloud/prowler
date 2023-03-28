import threading
from datetime import datetime

from botocore.client import ClientError
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.aws_provider import generate_regional_clients


################## Organizations
class Organizations:
    def __init__(self, audit_info):
        self.service = "backup"
        self.session = audit_info.audit_session
        self.audited_account = audit_info.audited_account
        self.audit_resources = audit_info.audit_resources
        self.regional_clients = generate_regional_clients(self.service, audit_info)
        self.backup_vaults = []
        self.__threading_call__(self.__list_backup_vaults__)
        self.backup_plans = []
        self.__threading_call__(self.__list_backup_plans__)

    def __threading_call__(self, call):
        threads = []
        for regional_client in self.regional_clients.values():
            threads.append(threading.Thread(target=call, args=(regional_client,)))
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    def __list_backup_vaults__(self, regional_client):
        logger.info("Backup - Listing Backup Vaults...")
        try:
            list_backup_vaults_paginator = regional_client.get_paginator(
                "list_backup_vaults"
            )
            for page in list_backup_vaults_paginator.paginate():
                for configuration in page["BackupVaultList"]:
                    if not self.audit_resources or (
                        is_resource_filtered(
                            configuration["BackupVaultArn"],
                            self.audit_resources,
                        )
                    ):
                        self.backup_vaults.append(
                            BackupVault(
                                arn=configuration["BackupVaultArn"],
                                name=configuration["BackupVaultName"],
                                region=regional_client.region,
                                encryption=configuration["EncryptionKeyArn"],
                                recovery_points=configuration["NumberOfRecoveryPoints"],
                                locked=configuration["Locked"],
                                min_retention_days=configuration["MinRetentionDays"],
                                max_retention_days=configuration["MaxRetentionDays"],
                            )
                        )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __list_backup_plans__(self, regional_client):
        logger.info("Backup - Listing Backup Plans...")
        try:
            list_backup_plans_paginator = regional_client.get_paginator(
                "list_backup_plans"
            )
            for page in list_backup_plans_paginator.paginate():
                for configuration in page["BackupPlansList"]:
                    if not self.audit_resources or (
                        is_resource_filtered(
                            configuration["BackupPlanArn"],
                            self.audit_resources,
                        )
                    ):
                        self.backup_plans.append(
                            BackupPlan(
                                arn=configuration["BackupPlanArn"],
                                id=configuration["BackupPlanId"],
                                region=regional_client.region,
                                name=configuration["BackupPlanName"],
                                version_id=configuration["VersionId"],
                                last_execution_date=configuration["LastExecutionDate"],
                                advanced_settings=configuration[
                                    "AdvancedBackupSettings"
                                ],
                            )
                        )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class BackupVault(BaseModel):
    arn: str
    name: str
    region: str
    encryption: str
    recovery_points: int
    locked: bool
    min_retention_days: int
    max_retention_days: int


class BackupPlan(BaseModel):
    arn: str
    id: str
    region: str
    name: str
    version_id: str
    last_execution_date: datetime
    advanced_settings: list
