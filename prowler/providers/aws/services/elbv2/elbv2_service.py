from typing import Dict, Optional

from botocore.client import ClientError
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class ELBv2(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.loadbalancersv2 = {}
        self.__threading_call__(self._describe_load_balancers)
        self.__threading_call__(self._describe_listeners, self.loadbalancersv2.items())
        self.__threading_call__(
            self._describe_load_balancer_attributes, self.loadbalancersv2.items()
        )
        self.__threading_call__(
            self._describe_rules,
            [
                (listener_arn, listener)
                for lb in self.loadbalancersv2.values()
                for listener_arn, listener in lb.listeners.items()
            ],
        )
        self.__threading_call__(self._describe_tags, self.loadbalancersv2.items())

    def _describe_load_balancers(self, regional_client):
        logger.info("ELBv2 - Describing load balancers...")
        try:
            describe_elbv2_paginator = regional_client.get_paginator(
                "describe_load_balancers"
            )
            for page in describe_elbv2_paginator.paginate():
                for elbv2 in page["LoadBalancers"]:
                    if not self.audit_resources or (
                        is_resource_filtered(
                            elbv2["LoadBalancerArn"], self.audit_resources
                        )
                    ):
                        self.loadbalancersv2[elbv2["LoadBalancerArn"]] = LoadBalancerv2(
                            name=elbv2["LoadBalancerName"],
                            region=regional_client.region,
                            type=elbv2["Type"],
                            dns=elbv2.get("DNSName", None),
                            scheme=elbv2.get("Scheme", None),
                            security_groups=elbv2.get("SecurityGroups", []),
                            availability_zones={
                                az["ZoneName"]: az["SubnetId"]
                                for az in elbv2.get("AvailabilityZones", [])
                            },
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_listeners(self, load_balancer):
        logger.info("ELBv2 - Describing listeners...")
        try:
            # load_balancer is a tuple with the LoadBalancerArn and the LoadBalancer object
            regional_client = self.regional_clients[load_balancer[1].region]

            describe_elbv2_paginator = regional_client.get_paginator(
                "describe_listeners"
            )

            for page in describe_elbv2_paginator.paginate(
                LoadBalancerArn=load_balancer[0]
            ):
                for listener in page["Listeners"]:
                    load_balancer[1].listeners[listener["ListenerArn"]] = Listenerv2(
                        region=regional_client.region,
                        port=listener.get("Port", 0),
                        ssl_policy=listener.get("SslPolicy", ""),
                        protocol=listener.get("Protocol", ""),
                    )

        except ClientError as error:
            if error.response["Error"]["Code"] == "LoadBalancerNotFound":
                logger.warning(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            else:
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_load_balancer_attributes(self, load_balancer):
        logger.info("ELBv2 - Describing attributes...")
        try:
            regional_client = self.regional_clients[load_balancer[1].region]

            for attribute in regional_client.describe_load_balancer_attributes(
                LoadBalancerArn=load_balancer[0]
            )["Attributes"]:
                if attribute["Key"] == "routing.http.desync_mitigation_mode":
                    load_balancer[1].desync_mitigation_mode = attribute["Value"]
                if attribute["Key"] == "load_balancing.cross_zone.enabled":
                    load_balancer[1].cross_zone_load_balancing = attribute["Value"]
                if attribute["Key"] == "deletion_protection.enabled":
                    load_balancer[1].deletion_protection = attribute["Value"]
                if attribute["Key"] == "access_logs.s3.enabled":
                    load_balancer[1].access_logs = attribute["Value"]
                if (
                    attribute["Key"]
                    == "routing.http.drop_invalid_header_fields.enabled"
                ):
                    load_balancer[1].drop_invalid_header_fields = attribute["Value"]

        except ClientError as error:
            if error.response["Error"]["Code"] == "LoadBalancerNotFound":
                logger.warning(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            else:
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_rules(self, listener):
        logger.info("ELBv2 - Describing Rules...")
        try:
            # listener is a tuple with the ListenerArn and the Listener object
            regional_client = self.regional_clients[listener[1].region]

            for rule in regional_client.describe_rules(ListenerArn=listener[0])[
                "Rules"
            ]:
                listener[1].rules.append(
                    ListenerRule(
                        arn=rule["RuleArn"],
                        actions=rule["Actions"],
                        conditions=rule["Conditions"],
                    )
                )
        except ClientError as error:
            if error.response["Error"]["Code"] == "ListenerNotFound":
                logger.warning(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            else:
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_tags(self, load_balancer):
        logger.info("ELBv2 - List Tags...")
        try:
            regional_client = self.regional_clients[load_balancer[1].region]

            load_balancer[1].tags = regional_client.describe_tags(
                ResourceArns=[load_balancer[0]]
            )["TagDescriptions"][0].get("Tags", [])
        except ClientError as error:
            if error.response["Error"]["Code"] == "LoadBalancerNotFound":
                logger.warning(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            else:
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class ListenerRule(BaseModel):
    arn: str
    actions: list[dict]
    conditions: list[dict]


class Listenerv2(BaseModel):
    region: str
    port: int
    protocol: str
    ssl_policy: str
    rules: list[ListenerRule] = []


class LoadBalancerv2(BaseModel):
    name: str
    region: str
    type: str
    access_logs: Optional[str]
    desync_mitigation_mode: Optional[str]
    deletion_protection: Optional[str]
    dns: Optional[str]
    drop_invalid_header_fields: Optional[str]
    cross_zone_load_balancing: Optional[str]
    listeners: Dict[str, Listenerv2] = {}
    scheme: Optional[str]
    security_groups: list[str] = []
    # Key: ZoneName, Value: SubnetId
    availability_zones: Dict[str, str] = {}
    tags: Optional[list] = []
