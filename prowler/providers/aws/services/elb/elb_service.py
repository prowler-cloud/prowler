from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class ELB(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.loadbalancers = {}
        self.__threading_call__(self._describe_load_balancers)
        self.__threading_call__(
            self._describe_load_balancer_attributes, self.loadbalancers.values()
        )
        self.__threading_call__(self._describe_tags, self.loadbalancers.values())

    def _describe_load_balancers(self, regional_client):
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

                        self.loadbalancers[arn] = LoadBalancer(
                            name=elb["LoadBalancerName"],
                            dns=elb["DNSName"],
                            region=regional_client.region,
                            scheme=elb["Scheme"],
                            listeners=listeners,
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_load_balancer_attributes(self, load_balancer):
        logger.info("ELB - Describing attributes...")
        try:
            regional_client = self.regional_clients[load_balancer.region]
            attributes = regional_client.describe_load_balancer_attributes(
                LoadBalancerName=load_balancer.name
            )["LoadBalancerAttributes"]

            load_balancer.access_logs = attributes.get("AccessLog", {}).get(
                "Enabled", False
            )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_tags(self, load_balancer):
        logger.info("ELB - List Tags...")
        try:
            regional_client = self.regional_clients[load_balancer.region]

            tags = regional_client.describe_tags(
                LoadBalancerNames=[load_balancer.name]
            )["TagDescriptions"][0].get("Tags", [])

            load_balancer.tags = tags

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
    access_logs: Optional[bool]
    listeners: list[Listener]
    tags: Optional[list] = []
