from typing import Optional

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class GuardDuty(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.detectors = []
        self.organization_admin_accounts = []
        self.__threading_call__(self._list_detectors)
        self.__threading_call__(self._get_detector, self.detectors)
        self._list_findings()
        self._list_members()
        self._get_administrator_account()
        self._list_tags_for_resource()
        self.__threading_call__(self._list_organization_admin_accounts)
        self.__threading_call__(
            self._describe_organization_configuration, self.detectors
        )

    def _list_detectors(self, regional_client):
        logger.info("GuardDuty - listing detectors...")
        try:
            detectors = False
            list_detectors_paginator = regional_client.get_paginator("list_detectors")
            for page in list_detectors_paginator.paginate():
                for detector in page["DetectorIds"]:
                    detectors = True
                    arn = f"arn:{self.audited_partition}:guardduty:{regional_client.region}:{self.audited_account}:detector/{detector}"
                    if not self.audit_resources or (
                        is_resource_filtered(arn, self.audit_resources)
                    ):
                        self.detectors.append(
                            Detector(
                                id=detector,
                                arn=arn,
                                region=regional_client.region,
                                enabled_in_account=True,
                            )
                        )
            if not detectors:
                self.detectors.append(
                    Detector(
                        id="detector/unknown",
                        arn=self.get_unknown_arn(
                            region=regional_client.region, resource_type="detector"
                        ),
                        region=regional_client.region,
                        enabled_in_account=False,
                    )
                )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_detector(self, detector):
        logger.info("GuardDuty - getting detector info...")
        try:
            if detector.id and detector.enabled_in_account:
                detector_info = self.regional_clients[detector.region].get_detector(
                    DetectorId=detector.id
                )
                if detector_info.get("Status", "DISABLED") == "ENABLED":
                    detector.status = True

                data_sources = detector_info.get("DataSources", {})

                s3_logs = data_sources.get("S3Logs", {})
                if s3_logs.get("Status", "DISABLED") == "ENABLED":
                    detector.s3_protection = True

                detector.eks_audit_log_protection = (
                    True
                    if data_sources.get("Kubernetes", {})
                    .get("AuditLogs", {})
                    .get("Status", "DISABLED")
                    == "ENABLED"
                    else False
                )

                detector.ec2_malware_protection = (
                    True
                    if data_sources.get("MalwareProtection", {})
                    .get("ScanEc2InstanceWithFindings", {})
                    .get("EbsVolumes", {})
                    .get("Status", "DISABLED")
                    == "ENABLED"
                    else False
                )

                for feat in detector_info.get("Features", []):
                    if (
                        feat.get("Name", "") == "RDS_LOGIN_EVENTS"
                        and feat.get("Status", "DISABLED") == "ENABLED"
                    ):
                        detector.rds_protection = True
                    elif (
                        feat.get("Name", "") == "LAMBDA_NETWORK_LOGS"
                        and feat.get("Status", "DISABLED") == "ENABLED"
                    ):
                        detector.lambda_protection = True
                    elif (
                        feat.get("Name", "") == "EKS_RUNTIME_MONITORING"
                        and feat.get("Status", "DISABLED") == "ENABLED"
                    ):
                        detector.eks_runtime_monitoring = True

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
            )

    def _get_administrator_account(self):
        logger.info("GuardDuty - getting administrator account...")
        try:
            for detector in self.detectors:
                if detector.id and detector.enabled_in_account:
                    try:
                        regional_client = self.regional_clients[detector.region]
                        detector_administrator = (
                            regional_client.get_administrator_account(
                                DetectorId=detector.id
                            )
                        )
                        detector_administrator_account = detector_administrator.get(
                            "Administrator"
                        )
                        if detector_administrator_account:
                            detector.administrator_account = (
                                detector_administrator_account.get("AccountId")
                            )
                    except Exception as error:
                        logger.error(
                            f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                        )
                        continue

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
            )

    def _list_members(self):
        logger.info("GuardDuty - listing members...")
        try:
            for detector in self.detectors:
                if detector.id and detector.enabled_in_account:
                    try:
                        regional_client = self.regional_clients[detector.region]
                        list_members_paginator = regional_client.get_paginator(
                            "list_members"
                        )
                        for page in list_members_paginator.paginate(
                            DetectorId=detector.id,
                        ):
                            for member in page["Members"]:
                                detector.member_accounts.append(member.get("AccountId"))
                    except Exception as error:
                        logger.error(
                            f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                        )
                        continue
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
            )

    def _list_findings(self):
        logger.info("GuardDuty - listing findings...")
        try:
            for detector in self.detectors:
                if detector.id and detector.enabled_in_account:
                    regional_client = self.regional_clients[detector.region]
                    list_findings_paginator = regional_client.get_paginator(
                        "list_findings"
                    )
                    for page in list_findings_paginator.paginate(
                        DetectorId=detector.id,
                        FindingCriteria={
                            "Criterion": {
                                "severity": {
                                    "Eq": [
                                        "8",
                                    ],
                                },
                                "service.archived": {
                                    "Eq": [
                                        "false",
                                    ],
                                },
                            }
                        },
                    ):
                        for finding in page["FindingIds"]:
                            detector.findings.append(finding)

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
            )

    def _list_tags_for_resource(self):
        logger.info("Guardduty - List Tags...")
        try:
            for detector in self.detectors:
                if detector.arn and detector.enabled_in_account:
                    regional_client = self.regional_clients[detector.region]
                    response = regional_client.list_tags_for_resource(
                        ResourceArn=detector.arn
                    )["Tags"]
                    detector.tags = [response]
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
            )

    def _list_organization_admin_accounts(self, regional_client):
        """List GuardDuty delegated administrator accounts for the organization.

        This API is only available to the organization management account or
        a delegated administrator account.
        """
        logger.info("GuardDuty - listing organization admin accounts...")
        try:
            paginator = regional_client.get_paginator(
                "list_organization_admin_accounts"
            )
            for page in paginator.paginate():
                for admin in page.get("AdminAccounts", []):
                    admin_account = OrganizationAdminAccount(
                        admin_account_id=admin.get("AdminAccountId"),
                        admin_status=admin.get("AdminStatus"),
                        region=regional_client.region,
                    )
                    # Avoid duplicates across regions for the same admin account
                    if not any(
                        existing.admin_account_id == admin_account.admin_account_id
                        and existing.region == admin_account.region
                        for existing in self.organization_admin_accounts
                    ):
                        self.organization_admin_accounts.append(admin_account)
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_organization_configuration(self, detector):
        """Describe the organization configuration for a GuardDuty detector.

        This provides information about auto-enable settings for the organization.
        """
        logger.info("GuardDuty - describing organization configuration...")
        try:
            if detector.id and detector.enabled_in_account:
                regional_client = self.regional_clients[detector.region]
                org_config = regional_client.describe_organization_configuration(
                    DetectorId=detector.id
                )
                detector.organization_auto_enable = org_config.get("AutoEnable", False)
                detector.organization_auto_enable_members = org_config.get(
                    "AutoEnableOrganizationMembers", "NONE"
                )
                detector.organization_member_limit_reached = org_config.get(
                    "MemberAccountLimitReached", False
                )
        except Exception as error:
            # This API may fail if not running from management or delegated admin account
            logger.error(
                f"{detector.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class OrganizationAdminAccount(BaseModel):
    """Represents a GuardDuty delegated administrator account."""

    admin_account_id: str
    admin_status: str  # ENABLED or DISABLE_IN_PROGRESS
    region: str


class Detector(BaseModel):
    id: str
    arn: str
    region: str
    enabled_in_account: bool
    status: bool = None
    findings: list = []
    member_accounts: list = []
    administrator_account: str = None
    tags: Optional[list] = []
    s3_protection: bool = False
    rds_protection: bool = False
    eks_audit_log_protection: bool = False
    eks_runtime_monitoring: bool = False
    lambda_protection: bool = False
    ec2_malware_protection: bool = False
    # Organization configuration fields
    organization_auto_enable: bool = False
    organization_auto_enable_members: str = "NONE"  # NEW, ALL, or NONE
    organization_member_limit_reached: bool = False
