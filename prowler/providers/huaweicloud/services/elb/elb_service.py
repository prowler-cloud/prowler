from typing import List, Optional

from prowler.lib.logger import logger
from prowler.providers.huaweicloud.lib.service.service import HuaweiCloudService
from prowler.providers.huaweicloud.models import HuaweiCloudBaseModel


class ELB(HuaweiCloudService):
    """
    ELB (Elastic Load Balancer) service class for Huawei Cloud.

    This class provides methods to interact with Huawei Cloud ELB service
    to retrieve load balancers and their listeners.
    """

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)

        self.load_balancers: List[LoadBalancer] = []
        self.listeners: List[Listener] = []

        self.__threading_call__(self._list_load_balancers)
        self.__threading_call__(self._list_listeners)

    def _list_load_balancers(self, regional_client):
        """List all ELB load balancers in the region."""
        region = getattr(regional_client, "region", "unknown")
        logger.info(f"ELB - Listing Load Balancers in {region}...")

        try:
            from huaweicloudsdkelb.v3 import ListLoadBalancersRequest

            request = ListLoadBalancersRequest()
            response = self._call_with_retries(
                regional_client.list_load_balancers, request
            )

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
                            id=getattr(lb_data, "id", None) or "",
                            name=getattr(lb_data, "name", None) or "",
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

    def _list_listeners(self, regional_client):
        """List all ELB listeners in the region."""
        region = getattr(regional_client, "region", "unknown")
        logger.info(f"ELB - Listing Listeners in {region}...")

        try:
            from huaweicloudsdkelb.v3 import (
                ListListenersRequest,
                ShowSecurityPolicyRequest,
            )

            policy_cache = {}
            limit = 2000
            marker = None

            while True:
                request = ListListenersRequest(limit=limit, marker=marker)
                response = self._call_with_retries(
                    regional_client.list_listeners, request
                )
                listeners = (
                    getattr(response, "listeners", None) or [] if response else []
                )

                for lis_data in listeners:
                    security_policy_id = (
                        getattr(lis_data, "security_policy_id", None) or ""
                    )
                    security_policy_protocols = None
                    if security_policy_id:
                        if security_policy_id not in policy_cache:
                            policy_cache[security_policy_id] = (
                                self._get_security_policy_protocols(
                                    regional_client,
                                    security_policy_id,
                                    ShowSecurityPolicyRequest,
                                )
                            )
                        security_policy_protocols = policy_cache[security_policy_id]

                    self.listeners.append(
                        Listener(
                            id=getattr(lis_data, "id", None) or "",
                            name=getattr(lis_data, "name", None) or "",
                            protocol=getattr(lis_data, "protocol", None) or "",
                            protocol_port=getattr(lis_data, "protocol_port", 0) or 0,
                            tls_ciphers_policy=(
                                getattr(lis_data, "tls_ciphers_policy", None) or ""
                            ),
                            security_policy_id=security_policy_id,
                            security_policy_protocols=security_policy_protocols,
                            region=region,
                        )
                    )

                page_info = getattr(response, "page_info", None) if response else None
                next_marker = (
                    getattr(page_info, "next_marker", None) if page_info else None
                )
                if not next_marker or len(listeners) < limit:
                    break
                marker = next_marker

        except Exception as error:
            logger.error(
                f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_security_policy_protocols(
        self, regional_client, security_policy_id: str, request_cls
    ) -> Optional[List[str]]:
        """Return configured TLS protocols for a custom ELB security policy, or None on error."""
        try:
            response = self._call_with_retries(
                regional_client.show_security_policy,
                request_cls(security_policy_id=security_policy_id),
            )
            policy = getattr(response, "security_policy", None) if response else None
            if policy is None:
                return None
            return list(getattr(policy, "protocols", None) or [])
        except Exception as error:
            region = getattr(regional_client, "region", "unknown")
            logger.error(
                f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return None


class LoadBalancer(HuaweiCloudBaseModel):
    """ELB Load Balancer model."""

    id: str
    name: str
    vip_address: str = ""
    public_ip: str = ""
    is_public: bool = False
    region: str = ""


class Listener(HuaweiCloudBaseModel):
    """ELB Listener model."""

    id: str
    name: str = ""
    protocol: str = ""
    protocol_port: int = 0
    tls_ciphers_policy: str = ""
    security_policy_id: str = ""
    security_policy_protocols: Optional[List[str]] = None
    region: str = ""
