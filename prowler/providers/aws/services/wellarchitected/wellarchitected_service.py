import threading
from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.aws_provider import generate_regional_clients


################################ WellArchitected
class WellArchitected:
    def __init__(self, audit_info):
        self.service = "wellarchitected"
        self.session = audit_info.audit_session
        self.audit_resources = audit_info.audit_resources
        self.regional_clients = generate_regional_clients(self.service, audit_info)
        self.workloads = []
        self.__threading_call__(self.__list_workloads__)
        self.__list_tags_for_resource__()

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

    def __list_workloads__(self, regional_client):
        logger.info("WellArchitected - Listing Workloads...")
        try:
            for workload in regional_client.list_workloads()["WorkloadSummaries"]:
                if not self.audit_resources or (
                    is_resource_filtered(workload["WorkloadArn"], self.audit_resources)
                ):
                    self.workloads.append(
                        Workload(
                            id=workload["WorkloadId"],
                            arn=workload["WorkloadArn"],
                            name=workload["WorkloadName"],
                            region=regional_client.region,
                            lenses=workload["Lenses"],
                            improvement_status=workload["ImprovementStatus"],
                            risks=workload["RiskCounts"],
                        )
                    )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __list_tags_for_resource__(self):
        logger.info("WellArchitected - Listing Tags...")
        try:
            for workload in self.workloads:
                regional_client = self.regional_clients[workload.region]
                response = regional_client.list_tags_for_resource(
                    WorkloadArn=workload.arn
                )["Tags"]
                workload.tags = [response]
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Workload(BaseModel):
    id: str
    arn: str
    name: str
    region: str
    lenses: list
    improvement_status: str
    risks: dict
    tags: Optional[list] = []
