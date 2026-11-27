from collections import defaultdict
from collections.abc import Iterable
from contextlib import nullcontext
from datetime import datetime
from threading import Lock
from typing import TYPE_CHECKING, Optional

from botocore.client import ClientError
from botocore.exceptions import PaginationError
from pydantic.v1 import BaseModel, ValidationError

from prowler.lib.logger import logger
from prowler.lib.resource_limit import (
    get_resource_scan_limit,
    limit_resources,
)
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService
from prowler.providers.aws.services.backup.ebs_recovery_evidence import (
    FRESHNESS_CHECK,
    POINT_ACTION,
    VAULT_ACTION,
    CollectionResult,
    Decision,
    EbsRecoveryEvidence,
    EbsRecoveryPoint,
    Vault,
    VaultDescription,
    log_unavailable,
    volume_scope,
)

if TYPE_CHECKING:
    from prowler.providers.aws.services.ec2.ec2_service import Volume


def _check_next_token(token: object, seen_tokens: set[str]) -> None:
    """Validate a continuation token after processing the current page.

    Args:
        token: The next token from AWS Backup. None or an empty string ends
            pagination.
        seen_tokens: Previously used tokens. A valid nonempty token is added
            to this set in place.

    Raises:
        PaginationError: If a non-None token is not a string or has already
            been seen.
    """
    # Stop before requesting an invalid page after the current rows are used.
    if token is None:
        return
    if not isinstance(token, str):
        raise PaginationError(message="Invalid AWS Backup pagination token")
    if token in seen_tokens:
        raise PaginationError(message="Repeated AWS Backup pagination token")
    if token:
        seen_tokens.add(token)


class Backup(AWSService):
    _ebs_evidence: EbsRecoveryEvidence | None = None

    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self._ebs_evidence_lock = Lock()
        self._ebs_evidence_audit = None
        if self._ebs_freshness_enabled():
            self._start_ebs_evidence()
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
        # Recovery points are listed first, then only the selected subset is
        # tagged and exposed for checks.
        self.recovery_points = []
        self.recovery_point_limit = get_resource_scan_limit(
            self.audit_config, "max_backup_recovery_points"
        )
        self.__threading_call__(self._list_recovery_points, self.backup_vaults or [])
        self._select_recovery_points_for_analysis()
        self.__threading_call__(self._list_tags, self.recovery_points)

    def _ebs_freshness_enabled(self) -> bool:
        return (
            self.provider.audit_config.get("aws_backup_ebs_recovery_evidence_enabled")
            is True
            and FRESHNESS_CHECK in self.provider.audit_metadata.expected_checks
        )

    def _start_ebs_evidence(self) -> EbsRecoveryEvidence:
        evidence = EbsRecoveryEvidence(self.audited_partition, self.audited_account)
        self._ebs_evidence = evidence
        self._ebs_evidence_audit = self.provider.audit_metadata
        return evidence

    def evaluate_ebs_recovery_points(
        self, volumes: Iterable["Volume"], hours: int
    ) -> dict[str, Decision]:
        """Collect missing Vault evidence and evaluate freshness for the audited volumes."""
        with self._ebs_evidence_lock:
            if not self._ebs_freshness_enabled():
                return {}
            evidence = self._ebs_evidence
            if (
                evidence is None
                or self._ebs_evidence_audit is not self.provider.audit_metadata
            ):
                evidence = self._start_ebs_evidence()

            regional_volumes = defaultdict(set)
            decisions = {}
            for volume in volumes:
                scope = evidence.scope(volume.region)
                if volume_scope(volume.arn) != scope:
                    log_unavailable(
                        POINT_ACTION,
                        scope,
                        "VolumeScopeMismatch",
                        volume_arn=volume.arn,
                    )
                    decisions[volume.arn] = Decision(
                        "SKIP", reason="VolumeScopeMismatch"
                    )
                else:
                    regional_volumes[volume.region].add(volume.arn)

            for region, arns in regional_volumes.items():
                if region not in evidence.discovery:
                    client = self.regional_clients.get(region)
                    if client is None:
                        evidence.store_discovery(
                            region, CollectionResult(error_code="RegionUnavailable")
                        )
                        log_unavailable(
                            VAULT_ACTION, evidence.scope(region), "RegionUnavailable"
                        )
                    else:
                        self._list_backup_vaults(client, evidence_only=True)
                for vault in sorted(
                    evidence.standard_vaults.get(region) or (),
                    key=lambda vault: vault.arn,
                ):
                    if vault not in evidence.points:
                        self._list_recovery_points(vault, evidence_only=True)
                decisions.update(evidence.evaluate(region, arns, hours))
            return decisions

    def _list_backup_vaults(self, regional_client, *, evidence_only=False):
        logger.info("Backup - Listing Backup Vaults...")
        region = regional_client.region
        evidence = self._ebs_evidence
        discovery = None
        read = nullcontext()
        if evidence is not None:
            discovery = CollectionResult[VaultDescription]()
            read = discovery.read(VAULT_ACTION, evidence.scope(region))
        add_legacy_vaults = not evidence_only
        seen_tokens = set()
        try:
            with read:
                list_backup_vaults_paginator = regional_client.get_paginator(
                    "list_backup_vaults"
                )
                for page in list_backup_vaults_paginator.paginate():
                    if discovery is not None:
                        discovery.rows.update(
                            VaultDescription.from_row(row)
                            for row in discovery.page_rows(page, "BackupVaultList")
                        )
                    if add_legacy_vaults:
                        try:
                            self._append_backup_vaults(
                                page.get("BackupVaultList"), region
                            )
                        except ValidationError as error:
                            if discovery is None:
                                raise
                            logger.error(
                                f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                            )
                            # Preserve the legacy cutoff while completing discovery.
                            add_legacy_vaults = False
                    _check_next_token(page.get("NextToken"), seen_tokens)
        except ClientError as error:
            logger.error(
                f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            if (
                add_legacy_vaults
                and error.response["Error"]["Code"] == "AccessDeniedException"
            ):
                if not self.backup_vaults:
                    self.backup_vaults = None
        except Exception as error:
            logger.error(
                f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        finally:
            if discovery is not None:
                evidence.store_discovery(region, discovery)

    def _append_backup_vaults(self, configurations, region):
        """Append matching vaults to the legacy vault list.

        Initialize the list if needed. Vaults appended before an invalid row
        remain in the list.

        Args:
            configurations: Vault mappings returned on the current Backup page.
            region: The AWS Region that returned the vaults.

        Raises:
            ValidationError: If a selected row fails BackupVault validation.
        """
        for configuration in configurations:
            if not self.audit_resources or is_resource_filtered(
                configuration.get("BackupVaultArn"), self.audit_resources
            ):
                if self.backup_vaults is None:
                    self.backup_vaults = []
                self.backup_vaults.append(
                    BackupVault(
                        arn=configuration.get("BackupVaultArn"),
                        name=configuration.get("BackupVaultName"),
                        region=region,
                        encryption=configuration.get("EncryptionKeyArn"),
                        recovery_points=configuration.get("NumberOfRecoveryPoints"),
                        locked=configuration.get("Locked"),
                        min_retention_days=configuration.get("MinRetentionDays"),
                        max_retention_days=configuration.get("MaxRetentionDays"),
                    )
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
                if backup_plan.region != regional_client.region:
                    continue
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

    def _list_recovery_points(self, backup_vault=None, *, evidence_only=False):
        logger.info("Backup - Listing Recovery Points...")
        if backup_vault is None:
            for vault in self.backup_vaults or []:
                self._list_recovery_points(vault)
            return

        evidence = self._ebs_evidence
        region = backup_vault.region
        captured = None
        read = nullcontext()
        if evidence is not None:
            vault = Vault(backup_vault.arn, backup_vault.name, region)
            captured = evidence.start_points(vault)
            if captured is not None:
                read = captured.read(POINT_ACTION, evidence.scope(region), vault.arn)

        seen_tokens = set()
        try:
            with read:
                regional_client = self.regional_clients[region]
                paginator = regional_client.get_paginator(
                    "list_recovery_points_by_backup_vault"
                )
                for page in paginator.paginate(BackupVaultName=backup_vault.name):
                    if not evidence_only:
                        for recovery_point in page.get("RecoveryPoints", []):
                            arn = recovery_point.get("RecoveryPointArn")
                            if arn:
                                rp = RecoveryPoint(
                                    arn=arn,
                                    id=arn.split(":")[-1],
                                    backup_vault_name=backup_vault.name,
                                    encrypted=recovery_point.get("IsEncrypted", False),
                                    creation_date=recovery_point.get("CreationDate"),
                                    backup_vault_region=region,
                                    region=region,
                                    tags=[],
                                )
                                self.recovery_points.append(rp)
                    if captured is not None:
                        captured.rows.update(
                            EbsRecoveryPoint.from_row(row)
                            for row in captured.page_rows(page, "RecoveryPoints")
                        )
                    _check_next_token(page.get("NextToken"), seen_tokens)
        except Exception as error:
            logger.error(
                f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _select_recovery_points_for_analysis(self):
        self.recovery_points = list(
            limit_resources(
                sorted(
                    self.recovery_points,
                    key=lambda rp: (
                        (
                            -rp.creation_date.timestamp()
                            if isinstance(rp.creation_date, datetime)
                            else 0.0
                        ),
                        rp.region or "",
                        rp.backup_vault_name or "",
                        rp.arn or "",
                        rp.id or "",
                    ),
                ),
                self.recovery_point_limit,
            )
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
    tags: Optional[list] = None


class BackupPlan(BaseModel):
    arn: str
    id: str
    region: str
    name: str
    version_id: str
    last_execution_date: Optional[datetime] = None
    advanced_settings: list
    tags: Optional[list] = None


class BackupReportPlan(BaseModel):
    arn: str
    region: str
    name: str
    last_attempted_execution_date: Optional[datetime] = None
    last_successful_execution_date: Optional[datetime] = None


class RecoveryPoint(BaseModel):
    arn: str
    id: str
    region: str
    backup_vault_name: str
    encrypted: bool
    backup_vault_region: str
    creation_date: Optional[datetime] = None
    tags: Optional[list] = None
