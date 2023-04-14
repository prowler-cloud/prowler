import threading

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.aws_provider import generate_regional_clients


################################ ResourceExplorer2
class ResourceExplorer2:
    def __init__(self, audit_info):
        self.service = "resource-explorer-2"
        self.session = audit_info.audit_session
        self.audit_resources = audit_info.audit_resources
        self.regional_clients = generate_regional_clients(self.service, audit_info)
        # If the region is not set in the audit profile,
        # we pick the first region from the regional clients list
        self.region = (
            audit_info.profile_region
            if audit_info.profile_region
            else list(self.regional_clients.keys())[0]
        )
        self.indexes = []
        self.__threading_call__(self.__list_indexes__)

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

    def __list_indexes__(self, regional_client):
        logger.info("ResourceExplorer - list indexes...")
        try:
            list_indexes_paginator = regional_client.get_paginator("list_indexes")
            for page in list_indexes_paginator.paginate():
                for index in page.get("Indexes"):
                    if not self.audit_resources or (
                        is_resource_filtered(index["Arn"], self.audit_resources)
                    ):
                        self.indexes.append(
                            Indexes(
                                arn=index["Arn"],
                                region=index["Region"],
                                type=index["Type"],
                            )
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Indexes(BaseModel):
    arn: str
    region: str
    type: str
