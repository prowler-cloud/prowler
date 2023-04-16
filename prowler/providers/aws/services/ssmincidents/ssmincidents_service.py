import threading

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.aws_provider import generate_regional_clients


################## SSMIncidents
class SSMIncidents:
    def __init__(self, audit_info):
        self.service = "ssm-incidents"
        self.session = audit_info.audit_session
        self.audited_account = audit_info.audited_account
        self.audited_partition = audit_info.audited_partition
        self.audit_resources = audit_info.audit_resources
        self.regional_clients = generate_regional_clients(self.service, audit_info)
        self.replication_sets = []
        self.__threading_call__(self.__list_replication_sets__)
        self.__get_replication_set__()
        self.response_plans = []
        self.__threading_call__(self.__list_response_plans__)
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

    def __list_replication_sets__(self, regional_client):
        logger.info("SSMIncidents - Listing Replication Sets...")
        try:
            list_replication_sets_paginator = regional_client.get_paginator(
                "list_replication_sets"
            )
            for page in list_replication_sets_paginator.paginate():
                for replication_set in page["replicationSetArns"]:
                    if not self.audit_resources or (
                        is_resource_filtered(replication_set, self.audit_resources)
                    ):
                        # The ARN is listed in all regions, but it's only one uniq replication set
                        self.replication_sets = [
                            ReplicationSet(
                                arn=replication_set,
                            )
                        ]
                        break
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
            )

    def __get_replication_set__(self):
        logger.info("SSMIncidents - Getting Replication Sets...")
        try:
            for replication_set in self.replication_sets:
                try:
                    regional_client = self.regional_clients["us-east-1"]
                    get_replication_set = regional_client.get_replication_set(
                        arn=replication_set.arn
                    )["replicationSet"]
                    replication_set.status = get_replication_set["status"]
                    for region in get_replication_set["regionMap"]:
                        replication_set.region_map.append(
                            RegionMap(
                                status=get_replication_set["regionMap"][region][
                                    "status"
                                ],
                                region=region,
                                sse_kms_id=get_replication_set["regionMap"][region][
                                    "sseKmsKeyId"
                                ],
                            )
                        )
                except Exception as error:
                    logger.error(
                        f"{error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
                    )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
            )

    def __list_response_plans__(self, regional_client):
        logger.info("SSMIncidents - Listing Response Plans...")
        try:
            list_response_plans_paginator = regional_client.get_paginator(
                "list_response_plans"
            )
            for page in list_response_plans_paginator.paginate():
                for response_plan in page["responsePlanSummaries"]:
                    self.response_plans.append(
                        ResponsePlan(
                            arn=response_plan["Arn"],
                            region=regional_client.region,
                            name=response_plan["Name"],
                        )
                    )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
            )

    def __list_tags_for_resource__(self):
        logger.info("SSMIncidents - List Tags...")
        try:
            for response_plan in self.response_plans:
                regional_client = self.regional_clients[response_plan.region]
                response = regional_client.list_tags_for_resource(
                    resourceArn=response_plan.arn
                )["tags"]
                response_plan.tags = response

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
            )


class RegionMap(BaseModel):
    status: str
    region: str
    sse_kms_id: str


class ReplicationSet(BaseModel):
    arn: str
    status: str = None
    region_map: list[RegionMap] = []


class ResponsePlan(BaseModel):
    arn: str
    name: str
    region: str
    tags: list = None
