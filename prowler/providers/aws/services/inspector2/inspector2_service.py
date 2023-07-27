import threading

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWS_Service


################################ Inspector2
class Inspector2(AWS_Service):
    def __init__(self, audit_info):
        # Call AWS_Service's __init__
        super().__init__(__class__.__name__, audit_info)
        self.inspectors = []
        self.__threading_call__(self.__batch_get_account_status__)
        self.__list_findings__()

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

    def __batch_get_account_status__(self, regional_client):
        # We use this function to check if inspector2 is enabled
        logger.info("Inspector2 - batch_get_account_status...")
        try:
            batch_get_account_status = regional_client.batch_get_account_status()[
                "accounts"
            ][0]
            self.inspectors.append(
                Inspector(
                    id=self.audited_account,
                    status=batch_get_account_status.get("state").get("status"),
                    region=regional_client.region,
                )
            )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __list_findings__(self):
        logger.info("Inspector2 - listing findings...")
        try:
            for inspector in self.inspectors:
                try:
                    regional_client = self.regional_clients[inspector.region]
                    list_findings_paginator = regional_client.get_paginator(
                        "list_findings"
                    )
                    for page in list_findings_paginator.paginate():
                        for finding in page["findings"]:
                            if not self.audit_resources or (
                                is_resource_filtered(
                                    finding["findingArn"], self.audit_resources
                                )
                            ):
                                inspector.findings.append(
                                    InspectorFinding(
                                        arn=finding["findingArn"],
                                        region=regional_client.region,
                                        severity=finding.get("severity"),
                                        status=finding.get("status"),
                                        title=finding.get("title"),
                                    )
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


class InspectorFinding(BaseModel):
    arn: str
    region: str
    severity: str
    status: str
    title: str


class Inspector(BaseModel):
    id: str
    region: str
    status: str
    findings: list[InspectorFinding] = []
