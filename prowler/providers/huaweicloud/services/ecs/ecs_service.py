from typing import Dict, Optional

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.huaweicloud.lib.service.service import HuaweiCloudService


class ECS(HuaweiCloudService):
    """
    ECS (Elastic Cloud Server) service class for Huawei Cloud.

    This class provides methods to interact with Huawei Cloud ECS service
    to retrieve instances and their details.
    """

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider, global_service=False)

        self.instances = {}

        if self.session.is_mock:
            self._load_mock_data()
            return

        self.__threading_call__(self._list_servers_details)

    def _load_mock_data(self):
        """Load mock data for testing."""
        region = "la-south-2"
        self.instances["ecs-mock-001"] = Instance(
            id="ecs-mock-001",
            name="web-server-public",
            region=region,
            status="ACTIVE",
            public_ip="123.45.67.89",
        )
        self.instances["ecs-mock-002"] = Instance(
            id="ecs-mock-002",
            name="app-server-private",
            region=region,
            status="ACTIVE",
            public_ip="",
        )
        self.instances["ecs-mock-003"] = Instance(
            id="ecs-mock-003",
            name="db-server-private",
            region=region,
            status="ACTIVE",
            public_ip="",
        )

    def _list_servers_details(self, regional_client):
        """List all ECS instances in the region."""
        region = getattr(regional_client, "region", "unknown")
        logger.info(f"ECS - Listing Servers in {region}...")

        try:
            from huaweicloudsdkecs.v2 import ListServersDetailsRequest

            request = ListServersDetailsRequest()
            request.limit = 50
            offset = 1

            while True:
                request.offset = offset
                response = self._call_with_retries(
                    regional_client.list_servers_details, request
                )

                if response and response.servers:
                    for server_data in response.servers:
                        if not self.audit_resources or is_resource_filtered(
                            server_data.id, self.audit_resources
                        ):
                            public_ip = ""
                            if (
                                hasattr(server_data, "access_i_pv4")
                                and server_data.access_i_pv4
                            ):
                                public_ip = server_data.access_i_pv4
                            elif (
                                hasattr(server_data, "addresses")
                                and server_data.addresses
                            ):
                                public_ip = self._extract_floating_ip(
                                    server_data.addresses
                                )

                            security_groups = {}
                            if (
                                hasattr(server_data, "security_groups")
                                and server_data.security_groups
                            ):
                                for sg in server_data.security_groups:
                                    sg_name = getattr(sg, "name", "")
                                    sg_id = getattr(sg, "id", sg_name)
                                    if sg_id:
                                        security_groups[sg_id] = sg_name

                            self.instances[server_data.id] = Instance(
                                id=server_data.id,
                                name=getattr(server_data, "name", server_data.id),
                                region=region,
                                status=getattr(server_data, "status", None) or "",
                                flavor=getattr(server_data, "flavor", None),
                                public_ip=public_ip,
                                vpc_id=self._extract_vpc_id(server_data),
                                enterprise_project_id=getattr(
                                    server_data, "enterprise_project_id", None
                                )
                                or "",
                                created_at=getattr(server_data, "created", None),
                                key_name=getattr(server_data, "key_name", None) or "",
                                security_groups=security_groups,
                            )

                    if len(response.servers) < 50:
                        break
                    offset += 50
                else:
                    break

        except Exception as error:
            logger.error(
                f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    @staticmethod
    def _extract_floating_ip(addresses):
        """Extract floating (public) IP from server addresses dict."""
        if not addresses:
            return ""
        for network_name, addr_list in addresses.items():
            if addr_list:
                for addr in addr_list:
                    ip_type = getattr(addr, "os_ext_ip_stype", "")
                    if ip_type == "floating":
                        return getattr(addr, "addr", "")
        return ""

    @staticmethod
    def _extract_vpc_id(server_data):
        """Extract VPC ID from server metadata or network interfaces."""
        metadata = getattr(server_data, "metadata", None)
        if metadata and isinstance(metadata, dict):
            vpc_id = metadata.get("__vpc_id", "")
            if vpc_id:
                return vpc_id
        return ""


class Instance(BaseModel):
    """ECS Instance model."""

    id: str
    name: str
    region: str
    status: str
    flavor: Optional[object] = None
    public_ip: str = ""
    vpc_id: str = ""
    enterprise_project_id: str = ""
    created_at: Optional[str] = None
    key_name: str = ""
    security_groups: Dict[str, str] = {}
