import threading
from dataclasses import dataclass

from lib.logger import logger
from providers.aws.aws_provider import generate_regional_clients


################## SECURITYHUB
class SECURITYHUB:
    def __init__(self, audit_info):
        self.service = "securityhub"
        self.session = audit_info.audit_session
        self.audited_account = audit_info.audited_account
        self.regional_clients = generate_regional_clients(self.service, audit_info)
        self.securityhubs = []
        self.__threading_call__(self.__list_analyzers__)

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

    def __list_analyzers__(self, regional_client):
        logger.info("SECURITYHUB - Getting Standards...")
        try:
            get_enabled_standards_paginator = regional_client.get_paginator(
                "get_enabled_standards"
            )
            standards = ""
            for page in get_enabled_standards_paginator.paginate():
                for standard in page["StandardsSubscriptions"]:
                    standards += f" {standard['StandardsArn'].split('/')[1]}"
            # Security Hub is not enabled in region
            if standards == "":
                self.securityhubs.append(
                    SecurityHub(
                        "",
                        "",
                        "NOT_AVAILABLE",
                        "",
                        regional_client.region,
                    )
                )
            else:
                # SecurityHub is active so get HubArn
                hub_arn = regional_client.describe_hub()["HubArn"]
                hub_id = hub_arn.split("/")[1]
                self.securityhubs.append(
                    SecurityHub(
                        hub_arn,
                        hub_id,
                        "ACTIVE",
                        standards,
                        regional_client.region,
                    )
                )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}: {error}"
            )


@dataclass
class SecurityHub:
    arn: str
    id: str
    status: str
    standards: str
    region: str

    def __init__(
        self,
        arn,
        id,
        status,
        standards,
        region,
    ):
        self.arn = arn
        self.id = id
        self.status = status
        self.standards = standards
        self.region = region
