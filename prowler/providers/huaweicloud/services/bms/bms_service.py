from typing import Dict

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.huaweicloud.lib.service.service import HuaweiCloudService


class BMS(HuaweiCloudService):
    """
    BMS (Bare Metal Server) service class for Huawei Cloud.

    This class provides methods to interact with Huawei Cloud BMS service
    to retrieve bare metal servers and their details.
    """

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider, global_service=False)

        self.servers = {}

        if self.session.is_mock:
            self._load_mock_data()
            return

        self.__threading_call__(self._list_bare_metal_servers)

    def _load_mock_data(self):
        """Load mock data for testing."""
        region = "la-south-2"
        self.servers["bms-mock-001"] = BareMetalServer(
            id="bms-mock-001", name="bms-public-server", region=region,
            status="ACTIVE", public_ip="123.45.67.89",
            security_groups={"sg-default": "default"},
        )
        self.servers["bms-mock-002"] = BareMetalServer(
            id="bms-mock-002", name="bms-private-server", region=region,
            status="ACTIVE", public_ip="",
            security_groups={"sg-custom": "custom-sg"},
        )
        self.servers["bms-mock-003"] = BareMetalServer(
            id="bms-mock-003", name="bms-secure-server", region=region,
            status="ACTIVE", public_ip="",
            security_groups={"sg-secure": "web-sg"},
        )

    def _list_bare_metal_servers(self, regional_client):
        """List all BMS instances in the region."""
        region = getattr(regional_client, "region", "unknown")
        logger.info(f"BMS - Listing Bare Metal Servers in {region}...")

        try:
            from huaweicloudsdkbms.v1 import ListBareMetalServersRequest

            request = ListBareMetalServersRequest()
            response = self._call_with_retries(
                regional_client.list_bare_metal_servers, request
            )

            if response and response.servers:
                for server_data in response.servers:
                    if not self.audit_resources or is_resource_filtered(
                        server_data.id, self.audit_resources
                    ):
                        public_ip = self._extract_floating_ip(
                            getattr(server_data, "addresses", None)
                        )

                        security_groups = {}
                        if hasattr(server_data, "security_groups") and server_data.security_groups:
                            for sg in server_data.security_groups:
                                sg_name = getattr(sg, "name", "")
                                sg_id = getattr(sg, "id", sg_name)
                                if sg_id:
                                    security_groups[sg_id] = sg_name

                        self.servers[server_data.id] = BareMetalServer(
                            id=server_data.id,
                            name=getattr(server_data, "name", server_data.id),
                            region=region,
                            status=getattr(server_data, "status", None) or "",
                            public_ip=public_ip,
                            security_groups=security_groups,
                        )

        except Exception as error:
            logger.error(
                f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    @staticmethod
    def _extract_floating_ip(addresses):
        """Extract floating (public) IP from server addresses dict."""
        if not addresses:
            return ""
        for net_name, net_addrs in addresses.items():
            if net_addrs:
                for addr in net_addrs:
                    ip_type = getattr(addr, "os_ext_ips_type", "")
                    if ip_type == "floating":
                        return getattr(addr, "addr", "")
        return ""


class BareMetalServer(BaseModel):
    """BMS Bare Metal Server model."""

    id: str
    name: str
    region: str
    status: str
    public_ip: str = ""
    security_groups: Dict[str, str] = {}
