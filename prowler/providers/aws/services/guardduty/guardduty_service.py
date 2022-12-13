import threading

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.aws.aws_provider import generate_regional_clients


################################ GuardDuty
class GuardDuty:
    def __init__(self, audit_info):
        self.service = "guardduty"
        self.session = audit_info.audit_session
        self.regional_clients = generate_regional_clients(self.service, audit_info)
        self.detectors = []
        self.__threading_call__(self.__list_detectors__)
        self.__get_detector__(self.regional_clients)
        self.__list_findings__(self.regional_clients)

    def __get_session__(self):
        return self.session

    def __threading_call__(self, call):
        threads = []
        for regional_client in self.regional_clients.values():
            threads.append(threading.Thread(target=call, args=(regional_client,)))
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    def __list_detectors__(self, regional_client):
        logger.info("GuardDuty - listing detectors...")
        try:
            list_detectors_paginator = regional_client.get_paginator("list_detectors")
            for page in list_detectors_paginator.paginate():
                for detector in page["DetectorIds"]:
                    self.detectors.append(
                        Detector(id=detector, region=regional_client.region)
                    )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __get_detector__(self, regional_clients):
        logger.info("GuardDuty - getting detector info...")
        try:
            for detector in self.detectors:
                regional_client = regional_clients[detector.region]
                detector_info = regional_client.get_detector(DetectorId=detector.id)
                if "Status" in detector_info and detector_info["Status"] == "ENABLED":
                    detector.status = True

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __list_findings__(self, regional_clients):
        logger.info("GuardDuty - listing findings...")
        try:
            for detector in self.detectors:
                regional_client = regional_clients[detector.region]
                list_findings_paginator = regional_client.get_paginator("list_findings")
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
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Detector(BaseModel):
    id: str
    # there is no arn for a guardduty detector but we want it filled for the reports
    arn: str = ""
    region: str
    status: bool = None
    findings: list = []
