from typing import List, Optional

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.huaweicloud.lib.service.service import HuaweiCloudService


class ELB(HuaweiCloudService):
    """
    ELB (Elastic Load Balancer) service class for Huawei Cloud.

    This class provides methods to interact with Huawei Cloud ELB service
    to retrieve load balancers and their listeners.
    """

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)

        self.load_balancers: List[LoadBalancer] = []

        if self.session.is_mock:
            self._load_mock_data()
            return

        self._list_load_balancers()

    def _load_mock_data(self):
        """Load mock data for testing."""
        region = "la-south-2"
        self.load_balancers = [
            LoadBalancer(
                id="elb-mock-001", name="public-lb", vip_address="192.168.1.10",
                public_ip="123.45.67.100", is_public=True, region=region,
            ),
            LoadBalancer(
                id="elb-mock-002", name="internal-lb-1", vip_address="192.168.1.20",
                public_ip="", is_public=False, region=region,
            ),
            LoadBalancer(
                id="elb-mock-003", name="internal-lb-2", vip_address="192.168.1.30",
                public_ip="", is_public=False, region=region,
            ),
        ]

    def _list_load_balancers(self):
        """List all ELB load balancers across regions."""
        if not self.regional_clients:
            return

        for region, client in self.regional_clients.items():
            logger.info(f"ELB - Listing Load Balancers in {region}...")

            try:
                from huaweicloudsdkelb.v3 import ListLoadBalancersRequest

                request = ListLoadBalancersRequest()
                response = self._call_with_retries(
                    client.list_load_balancers, request
                )

                if response and response.loadbalancers:
                    for lb_data in response.loadbalancers:
                        vip_address = ""
                        if getattr(lb_data, "vip_address", None):
                            vip_address = lb_data.vip_address

                        public_ip = ""
                        if getattr(lb_data, "publicip", None):
                            public_ip = getattr(lb_data.publicip, "public_ip_address", "")

                        self.load_balancers.append(
                            LoadBalancer(
                                id=getattr(lb_data, "id", ""),
                                name=getattr(lb_data, "name", ""),
                                vip_address=vip_address,
                                public_ip=public_ip,
                                is_public=bool(public_ip),
                                region=region,
                            )
                        )

            except Exception as error:
                logger.error(
                    f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )


class LoadBalancer(BaseModel):
    """ELB Load Balancer model."""

    id: str
    name: str
    vip_address: str = ""
    public_ip: str = ""
    is_public: bool = False
    region: str = ""
