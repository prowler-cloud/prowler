from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.e2enetworks.lib.service.service import E2eNetworksService


class Network(E2eNetworksService):
    """Service class for E2E Networks network resources."""

    def __init__(self, provider):
        super().__init__("network", provider)
        self.vpcs: list[Vpc] = []
        self.reserved_ips: list[ReservedIp] = []
        self.vpc_tunnels: list[VpcTunnel] = []
        self._fetch_vpcs()
        self._fetch_reserved_ips()
        self._fetch_vpc_tunnels()

    def _fetch_vpcs(self):
        for location in self.provider.session.locations:
            try:
                vpcs = self.client.paginate("/vpc/list/", location=location)
                if not isinstance(vpcs, list):
                    continue
                for item in vpcs:
                    gateway_node = item.get("gateway_node", {}) or {}
                    self.vpcs.append(
                        Vpc(
                            network_id=str(item.get("network_id", "")),
                            name=item.get("name", ""),
                            location=location,
                            is_active=bool(item.get("is_active", False)),
                            state=item.get("state", ""),
                            ipv4_cidr=item.get("ipv4_cidr", ""),
                            vm_count=int(item.get("vm_count", 0)),
                            gateway_node_id=str(gateway_node.get("node_id", "")),
                            gateway_public_ip=gateway_node.get("ip_address_public", ""),
                        )
                    )
            except Exception as error:
                logger.error(
                    f"network - Error fetching VPCs in {location} -- "
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def _fetch_reserved_ips(self):
        for location in self.provider.session.locations:
            try:
                ips = self.client.get_data("/reserve_ips/", location=location)
                if not isinstance(ips, list):
                    continue

                for item in ips:
                    attached_nodes = item.get("floating_ip_attached_nodes", []) or []
                    self.reserved_ips.append(
                        ReservedIp(
                            reserve_id=str(item.get("reserve_id", "")),
                            ip_address=item.get("ip_address", ""),
                            location=location,
                            status=item.get("status", ""),
                            reserved_type=item.get("reserved_type", ""),
                            vm_id=item.get("vm_id"),
                            floating_ip_attached_nodes_count=len(attached_nodes),
                        )
                    )
            except Exception as error:
                logger.error(
                    f"network - Error fetching reserved IPs in {location} -- "
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def _fetch_vpc_tunnels(self):
        for vpc in self.vpcs:
            if not vpc.network_id:
                continue
            try:
                tunnels = self.client.get_data(
                    f"/vpc/tunnels/{vpc.network_id}/",
                    location=vpc.location,
                )
                if not isinstance(tunnels, list):
                    continue

                for item in tunnels:
                    self.vpc_tunnels.append(
                        VpcTunnel(
                            id=str(item.get("id", "")),
                            name=item.get("name", ""),
                            location=vpc.location,
                            local_vpc_network_id=vpc.network_id,
                            local_vpc_name=vpc.name,
                            status=item.get("status", ""),
                            is_peer_vpc_external=bool(
                                item.get("is_peer_vpc_external", False)
                            ),
                        )
                    )
            except Exception as error:
                logger.error(
                    f"network - Error fetching tunnels for VPC {vpc.network_id} -- "
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )


class Vpc(BaseModel):
    network_id: str
    name: str
    location: str
    is_active: bool = False
    state: str = ""
    ipv4_cidr: str = ""
    vm_count: int = 0
    gateway_node_id: str = ""
    gateway_public_ip: str = ""

    @property
    def resource_id(self) -> str:
        return self.network_id

    @property
    def resource_name(self) -> str:
        return self.name


class ReservedIp(BaseModel):
    reserve_id: str
    ip_address: str
    location: str
    status: str = ""
    reserved_type: str = ""
    vm_id: int | None = None
    floating_ip_attached_nodes_count: int = 0

    @property
    def resource_id(self) -> str:
        return self.reserve_id

    @property
    def resource_name(self) -> str:
        return self.ip_address


class VpcTunnel(BaseModel):
    id: str
    name: str
    location: str
    local_vpc_network_id: str
    local_vpc_name: str
    status: str = ""
    is_peer_vpc_external: bool = False

    @property
    def resource_id(self) -> str:
        return self.id

    @property
    def resource_name(self) -> str:
        return self.name
