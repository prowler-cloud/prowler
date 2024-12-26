from datetime import datetime
from typing import Optional

from botocore.client import ClientError
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class Backup(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.backup_plan_arn_template = f"arn:{self.audited_partition}:backup:{self.region}:{self.audited_account}:backup-plan"
        self.report_plan_arn_template = f"arn:{self.audited_partition}:backup:{self.region}:{self.audited_account}:report-plan"
        self.backup_vault_arn_template = f"arn:{self.audited_partition}:backup:{self.region}:{self.audited_account}:backup-vault"
        self.backup_vaults = []
        self.__threading_call__(self._list_backup_vaults)
        if self.backup_vaults is not None:
            self.__threading_call__(self._list_tags, self.backup_vaults)
        self.backup_plans = []
        self.__threading_call__(self._list_backup_plans)
        self.__threading_call__(self._list_tags, self.backup_plans)
        self.backup_report_plans = []
        self.__threading_call__(self._list_backup_report_plans)
        self.protected_resources = []
        self.__threading_call__(self._list_backup_selections)
        self.recovery_points = []
        self.__threading_call__(self._list_recovery_points)
        self.__threading_call__(self._list_tags, self.recovery_points)

    def _list_backup_vaults(self, regional_client):
        logger.info("Backup - Listing Backup Vaults...")
        try:
            list_backup_vaults_paginator = regional_client.get_paginator(
                "list_backup_vaults"
            )
            for page in list_backup_vaults_paginator.paginate():
                for configuration in page.get("BackupVaultList"):
                    if not self.audit_resources or (
                        is_resource_filtered(
                            configuration.get("BackupVaultArn"),
                            self.audit_resources,
                        )
                    ):
                        if self.backup_vaults is None:
                            self.backup_vaults = []
                        self.backup_vaults.append(
                            BackupVault(
                                arn=configuration.get("BackupVaultArn"),
                                name=configuration.get("BackupVaultName"),
                                region=regional_client.region,
                                encryption=configuration.get("EncryptionKeyArn"),
                                recovery_points=configuration.get(
                                    "NumberOfRecoveryPoints"
                                ),
                                locked=configuration.get("Locked"),
                                min_retention_days=configuration.get(
                                    "MinRetentionDays"
                                ),
                                max_retention_days=configuration.get(
                                    "MaxRetentionDays"
                                ),
                            )
                        )
        except ClientError as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            if error.response["Error"]["Code"] == "AccessDeniedException":
                if not self.backup_vaults:
                    self.backup_vaults = None
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_backup_plans(self, regional_client):
        logger.info("Backup - Listing Backup Plans...")
        try:
            list_backup_plans_paginator = regional_client.get_paginator(
                "list_backup_plans"
            )
            for page in list_backup_plans_paginator.paginate():
                for configuration in page.get("BackupPlansList"):
                    if not self.audit_resources or (
                        is_resource_filtered(
                            configuration.get("BackupPlanArn"),
                            self.audit_resources,
                        )
                    ):
                        self.backup_plans.append(
                            BackupPlan(
                                arn=configuration.get("BackupPlanArn"),
                                id=configuration.get("BackupPlanId"),
                                region=regional_client.region,
                                name=configuration.get("BackupPlanName"),
                                version_id=configuration.get("VersionId"),
                                last_execution_date=configuration.get(
                                    "LastExecutionDate"
                                ),
                                advanced_settings=configuration.get(
                                    "AdvancedBackupSettings", []
                                ),
                            )
                        )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_backup_report_plans(self, regional_client):
        logger.info("Backup - Listing Backup Report Plans...")

        try:
            list_backup_report_plans = regional_client.list_report_plans()[
                "ReportPlans"
            ]
            for backup_report_plan in list_backup_report_plans:
                if not self.audit_resources or (
                    is_resource_filtered(
                        backup_report_plan.get("ReportPlanArn"),
                        self.audit_resources,
                    )
                ):
                    self.backup_report_plans.append(
                        BackupReportPlan(
                            arn=backup_report_plan.get("ReportPlanArn"),
                            region=regional_client.region,
                            name=backup_report_plan.get("ReportPlanName"),
                            last_attempted_execution_date=backup_report_plan.get(
                                "LastAttemptedExecutionTime"
                            ),
                            last_successful_execution_date=backup_report_plan.get(
                                "LastSuccessfulExecutionTime"
                            ),
                        )
                    )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_backup_selections(self, regional_client):
        logger.info("Backup - Listing Backup Selections...")
        try:
            for backup_plan in self.backup_plans:
                paginator = regional_client.get_paginator("list_backup_selections")
                for page in paginator.paginate(BackupPlanId=backup_plan.id):
                    for selection in page.get("BackupSelectionsList", []):
                        selection_id = selection.get("SelectionId")
                        if selection_id:
                            backup_selection = regional_client.get_backup_selection(
                                BackupPlanId=backup_plan.id, SelectionId=selection_id
                            )["BackupSelection"]

                            self.protected_resources.extend(
                                backup_selection.get("Resources", [])
                            )

        except ClientError as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_tags(self, resource):
        try:
            if getattr(resource, "arn", None):
                tags = self.regional_clients[resource.region].list_tags(
                    ResourceArn=resource.arn
                )["Tags"]
                resource.tags = [tags] if tags else []
        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_recovery_points(self, regional_client):
        logger.info("Backup - Listing Recovery Points...")
        try:
            if self.backup_vaults:
                for backup_vault in self.backup_vaults:
                    paginator = regional_client.get_paginator(
                        "list_recovery_points_by_backup_vault"
                    )
                    for page in paginator.paginate(BackupVaultName=backup_vault.name):
                        for recovery_point in page.get("RecoveryPoints", []):
                            arn = recovery_point.get("RecoveryPointArn")
                            if arn:
                                self.recovery_points.append(
                                    RecoveryPoint(
                                        arn=arn,
                                        id=arn.split(":")[-1],
                                        backup_vault_name=backup_vault.name,
                                        encrypted=recovery_point.get(
                                            "IsEncrypted", False
                                        ),
                                        backup_vault_region=backup_vault.region,
                                        region=regional_client.region,
                                        tags=[],
                                    )
                                )
        except ClientError as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
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
    min_retention_days: int = None
    max_retention_days: int = None
    tags: Optional[list]


class BackupPlan(BaseModel):
    arn: str
    id: str
    region: str
    name: str
    version_id: str
    last_execution_date: Optional[datetime]
    advanced_settings: list
    tags: Optional[list]


class BackupReportPlan(BaseModel):
    arn: str
    region: str
    name: str
    last_attempted_execution_date: Optional[datetime]
    last_successful_execution_date: Optional[datetime]


class RecoveryPoint(BaseModel):
    arn: str
    id: str
    region: str
    backup_vault_name: str
    encrypted: bool
    backup_vault_region: str
    tags: Optional[list]
