import threading

from pydantic import BaseModel

from lib.logger import logger
from providers.aws.aws_provider import generate_regional_clients


################### ELB
class ELB:
    def __init__(self, audit_info):
        self.service = "elb"
        self.session = audit_info.audit_session
        self.regional_clients = generate_regional_clients(self.service, audit_info)
        self.loadbalancers = []
        self.__threading_call__(self.__describe_load_balancers__)

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


class Listener(BaseModel):
    protocol: str
    policies: list[str]


class LoadBalancer(BaseModel):
    name: str
    dns: str
    region: str
    scheme: str
    listeners: list[Listener]
