import threading

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
        self.inspectors_findings = []
        self.__threading_call__(self.__list_findings__)

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

    def __list_findings__(self, regional_client):
        logger.info("Inspector2 - listing findings...")
        try:
            list_findings_paginator = regional_client.get_paginator("list_findings")
            print("testing")
            for page in list_findings_paginator.paginate():
                for finding in page["findings"]:
                    if not self.audit_resources or (
                        is_resource_filtered(finding, self.audit_resources)
                    ):
                        print("testing", finding["findingArn"])
                        self.inspectors_findings.append(
                            InspectorFinding(
                                arn=finding["findingArn"],
                                region=regional_client.region,
                                severity=finding["severity"],
                                status=finding["status"],
                                title=finding["title"],
                            )
                        )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class InspectorFinding(BaseModel):
    arn: str
    region: str
    severity: str
    status: str
    title: str
