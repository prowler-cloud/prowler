import threading
from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.aws.aws_provider import generate_regional_clients


################### ELB
class ELB:
    def __init__(self, audit_info):
        self.service = "elb"
        self.session = audit_info.audit_session
        self.audited_partition = audit_info.audited_partition
        self.audited_account = audit_info.audited_account
        self.regional_clients = generate_regional_clients(self.service, audit_info)
        self.loadbalancers = []
        self.__threading_call__(self.__describe_load_balancers__)
        self.__threading_call__(self.__describe_load_balancer_attributes__)

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
                            arn=f"arn:{self.audited_partition}:elasticloadbalancing:{regional_client.region}:{self.audited_account}:loadbalancer/{elb['LoadBalancerName']}",
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
