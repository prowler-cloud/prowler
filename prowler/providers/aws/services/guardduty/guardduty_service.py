from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


################################ GuardDuty
class GuardDuty(AWSService):
    def __init__(self, audit_info):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, audit_info)
        self.detectors = []
        self.__threading_call__(self.__list_detectors__)
        self.__get_detector__()
        self.__list_findings__()
        self.__list_members__()
        self.__get_administrator_account__()
        self.__list_tags_for_resource__()

    def __list_detectors__(self, regional_client):
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
                                id=detector, arn=arn, region=regional_client.region
                            )
                        )
            if not detectors:
                self.detectors.append(
                    Detector(
                        id=self.audited_account,
                        arn=self.audited_account_arn,
                        region=regional_client.region,
                        enabled_in_account=False,
                    )
                )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __get_detector__(self):
        logger.info("GuardDuty - getting detector info...")
        try:
            for detector in self.detectors:
                try:
                    if detector.id and detector.enabled_in_account:
                        regional_client = self.regional_clients[detector.region]
                        detector_info = regional_client.get_detector(
                            DetectorId=detector.id
                        )
                        if (
                            "Status" in detector_info
                            and detector_info["Status"] == "ENABLED"
                        ):
                            detector.status = True
                except Exception as error:
                    logger.error(
                        f"{error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
                    )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
            )

    def __get_administrator_account__(self):
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

    def __list_members__(self):
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

    def __list_findings__(self):
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

    def __list_tags_for_resource__(self):
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
    enabled_in_account: bool = True
    status: bool = None
    findings: list = []
    member_accounts: list = []
    administrator_account: str = None
    tags: Optional[list] = []
