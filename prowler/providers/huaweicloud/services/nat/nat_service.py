from typing import List

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.huaweicloud.lib.service.service import HuaweiCloudService


class NAT(HuaweiCloudService):
    """
    NAT (Network Address Translation) service class for Huawei Cloud.

    This class provides methods to interact with Huawei Cloud NAT service
    to retrieve NAT gateways and DNAT rules.
    """

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)

        self.dnat_rules: List[DnatRule] = []

        if self.session.is_mock:
            self._load_mock_data()
            return

        self._list_dnat_rules()

    def _load_mock_data(self):
        """Load mock data for testing."""
        region = "la-south-2"
        self.dnat_rules = [
            DnatRule(
                id="dnat-mock-001",
                nat_gateway_id="nat-gw-001",
                floating_ip_address="1.2.3.4",
                external_service_port=22,
                internal_service_port=22,
                protocol="tcp",
                region=region,
            ),
            DnatRule(
                id="dnat-mock-002",
                nat_gateway_id="nat-gw-001",
                floating_ip_address="5.6.7.8",
                external_service_port=8080,
                internal_service_port=80,
                protocol="tcp",
                region=region,
            ),
        ]

    def _list_dnat_rules(self):
        """List all DNAT rules across regions."""
        if not self.regional_clients:
            return

        for region, client in self.regional_clients.items():
            logger.info(f"NAT - Listing DNAT Rules in {region}...")

            try:
                from huaweicloudsdknat.v2 import (
                    ListNatGatewayDnatRulesRequest,
                )

                request = ListNatGatewayDnatRulesRequest()
                response = self._call_with_retries(
                    client.list_nat_gateway_dnat_rules, request
                )

                if response and response.dnat_rules:
                    for rule_data in response.dnat_rules:
                        self.dnat_rules.append(
                            DnatRule(
                                id=getattr(rule_data, "id", ""),
                                nat_gateway_id=getattr(
                                    rule_data, "nat_gateway_id", ""
                                ),
                                floating_ip_address=getattr(
                                    rule_data, "floating_ip_address", ""
                                ),
                                external_service_port=getattr(
                                    rule_data, "external_service_port", 0
                                ),
                                internal_service_port=getattr(
                                    rule_data, "internal_service_port", 0
                                ),
                                protocol=getattr(rule_data, "protocol", "tcp"),
                                region=region,
                            )
                        )

            except Exception as error:
                logger.error(
                    f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )


class DnatRule(BaseModel):
    """DNAT Rule model."""

    id: str
    nat_gateway_id: str = ""
    floating_ip_address: str = ""
    external_service_port: int = 0
    internal_service_port: int = 0
    protocol: str = "tcp"
    region: str = ""
