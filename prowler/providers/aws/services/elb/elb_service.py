import threading
from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWS_Service


################### ELB
class ELB(AWS_Service):
    def __init__(self, audit_info):
        # Call AWS_Service's __init__
        super().__init__(__class__.__name__, audit_info)
        self.loadbalancers = []
        self.__threading_call__(self.__describe_load_balancers__)
        self.__threading_call__(self.__describe_load_balancer_attributes__)
        self.__describe_tags__()

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

    def __describe_load_balancers__(self, regional_client):
        logger.info("ELB - Describing load balancers...")
        try:
            describe_elb_paginator = regional_client.get_paginator(
                "describe_load_balancers"
            )
            for page in describe_elb_paginator.paginate():
                for elb in page["LoadBalancerDescriptions"]:
                    arn = f"arn:{self.audited_partition}:elasticloadbalancing:{regional_client.region}:{self.audited_account}:loadbalancer/{elb['LoadBalancerName']}"
                    if not self.audit_resources or (
                        is_resource_filtered(arn, self.audit_resources)
                    ):
                        listeners = []
                        for listener in elb["ListenerDescriptions"]:
                            listeners.append(
                                Listener(
                                    protocol=listener["Listener"]["Protocol"],
                                    policies=listener["PolicyNames"],
                                )
                            )
                        self.loadbalancers.append(
                            LoadBalancer(
                                name=elb["LoadBalancerName"],
                                arn=arn,
                                dns=elb["DNSName"],
                                region=regional_client.region,
                                scheme=elb["Scheme"],
                                listeners=listeners,
                            )
                        )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __describe_load_balancer_attributes__(self, regional_client):
        logger.info("ELB - Describing attributes...")
        try:
            for lb in self.loadbalancers:
                if lb.region == regional_client.region:
                    attributes = regional_client.describe_load_balancer_attributes(
                        LoadBalancerName=lb.name
                    )["LoadBalancerAttributes"]
                    if "AccessLog" in attributes:
                        lb.access_logs = attributes["AccessLog"]["Enabled"]

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __describe_tags__(self):
        logger.info("ELB - List Tags...")
        try:
            for lb in self.loadbalancers:
                regional_client = self.regional_clients[lb.region]
                response = regional_client.describe_tags(LoadBalancerNames=[lb.name])[
                    "TagDescriptions"
                ][0]
                lb.tags = response.get("Tags")
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Listener(BaseModel):
    protocol: str
    policies: list[str]


class LoadBalancer(BaseModel):
    name: str
    dns: str
    arn: str
    region: str
    scheme: str
    access_logs: Optional[bool]
    listeners: list[Listener]
    tags: Optional[list] = []
