from typing import List

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

        self._list_load_balancers()

    def _list_load_balancers(self):
        """List all ELB load balancers across regions."""
        if not self.regional_clients:
            return

        for region, client in self.regional_clients.items():
            logger.info(f"ELB - Listing Load Balancers in {region}...")

            try:
                from huaweicloudsdkelb.v3 import ListLoadBalancersRequest

                request = ListLoadBalancersRequest()
                response = self._call_with_retries(client.list_load_balancers, request)

                if response and response.loadbalancers:
                    for lb_data in response.loadbalancers:
                        vip_address = getattr(lb_data, "vip_address", "") or ""

                        # Public exposure is indicated by bound public IPs
                        # (publicips) or EIPs (eips) on the load balancer.
                        public_ip = ""
                        for public_ip_info in getattr(lb_data, "publicips", None) or []:
                            address = getattr(public_ip_info, "publicip_address", "")
                            if address:
                                public_ip = address
                                break
                        if not public_ip:
                            for eip_info in getattr(lb_data, "eips", None) or []:
                                address = getattr(eip_info, "eip_address", "")
                                if address:
                                    public_ip = address
                                    break

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
