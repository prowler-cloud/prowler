import threading

from botocore.client import ClientError
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.aws_provider import generate_regional_clients


################################ Inspector2
class Inspector2:
    def __init__(self, audit_info):
        self.service = "inspector2"
        self.session = audit_info.audit_session
        self.audited_account = audit_info.audited_account
        self.audit_resources = audit_info.audit_resources
        self.audited_partition = audit_info.audited_partition
        self.regional_clients = generate_regional_clients(self.service, audit_info)
        # If the region is not set in the audit profile,
        # we pick the first region from the regional clients list
        self.region = (
            audit_info.profile_region
            if audit_info.profile_region
            else list(self.regional_clients.keys())[0]
        )
        self.inspectors = []
        self.__get_configuration__()
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

    def __get_configuration__(self):
        # We use this function to check if inspector2 is enabled
        logger.info("Inspector2 - get configuration...")
        try:
            for regional_client in self.regional_clients.values():
                try:
                    regional_client.get_configuration()
                    self.inspectors.append(
                        Inspector(
                            id="Inspector2",
                            region=regional_client.region,
                        )
                    )
                except ClientError as error:
                    if error.response["Error"]["Code"] == "ResourceNotFoundException":
                        # Inspector not found in this region
                        continue
                    else:
                        logger.error(
                            f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                        )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
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
                                is_resource_filtered(finding, self.audit_resources)
                            ):
                                inspector.findings.append(
                                    InspectorFinding(
                                        arn=finding.get("findingArn"),
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
    findings: list[InspectorFinding] = []
