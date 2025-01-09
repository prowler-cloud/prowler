from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class GuardDuty(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.detectors = []
        self.__threading_call__(self._list_detectors)
        self.__threading_call__(self._get_detector, self.detectors)
        self._list_findings()
        self._list_members()
        self._get_administrator_account()
        self._list_tags_for_resource()

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
