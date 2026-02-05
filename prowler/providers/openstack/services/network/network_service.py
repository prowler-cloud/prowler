from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from openstack import exceptions as openstack_exceptions

from prowler.lib.logger import logger
from prowler.providers.openstack.lib.service.service import OpenStackService


class Network(OpenStackService):
    """Service wrapper using openstacksdk network (Neutron) APIs."""

    def __init__(self, provider) -> None:
        super().__init__(__class__.__name__, provider)
        self.client = self.connection.network
        self.security_groups: List[SecurityGroup] = []
        self.networks: List[NetworkResource] = []
        self.subnets: List[Subnet] = []
        self.ports: List[Port] = []
        self._list_security_groups()
        self._list_networks()
        self._list_subnets()
        self._list_ports()

    def _list_security_groups(self) -> None:
        """List all security groups with rules."""
        logger.info("Network - Listing security groups...")
        try:
            for sg in self.client.security_groups():
                # Parse security group rules
                rules = []
                for rule in getattr(sg, "security_group_rules", []):
                    rules.append(
                        SecurityGroupRule(
                            id=getattr(rule, "id", ""),
                            security_group_id=getattr(
                                rule, "security_group_id", ""
                            ),  # noqa: E501
                            direction=getattr(rule, "direction", "ingress"),
                            protocol=getattr(rule, "protocol", None),
                            ethertype=getattr(rule, "ethertype", "IPv4"),
                            port_range_min=getattr(
                                rule, "port_range_min", None
                            ),  # noqa: E501
                            port_range_max=getattr(
                                rule, "port_range_max", None
                            ),  # noqa: E501
                            remote_ip_prefix=getattr(
                                rule, "remote_ip_prefix", None
                            ),  # noqa: E501
                            remote_group_id=getattr(
                                rule, "remote_group_id", None
                            ),  # noqa: E501
                        )
                    )

                # Check if this is a default security group
                is_default = getattr(sg, "name", "") == "default"

                self.security_groups.append(
                    SecurityGroup(
                        id=getattr(sg, "id", ""),
                        name=getattr(sg, "name", ""),
                        description=getattr(sg, "description", ""),
                        security_group_rules=rules,
                        project_id=getattr(sg, "project_id", ""),
                        region=self.region,
                        is_default=is_default,
                        tags=getattr(sg, "tags", []),
                    )
                )
        except openstack_exceptions.SDKException as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- "  # noqa: E501
                f"Failed to list security groups: {error}"
            )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- "  # noqa: E501
                f"Unexpected error listing security groups: {error}"
            )

    def _list_networks(self) -> None:
        """List all networks."""
        logger.info("Network - Listing networks...")
        try:
            for net in self.client.networks():
                self.networks.append(
                    NetworkResource(
                        id=getattr(net, "id", ""),
                        name=getattr(net, "name", ""),
                        status=getattr(net, "status", ""),
                        admin_state_up=getattr(net, "admin_state_up", True),
                        shared=getattr(net, "shared", False),
                        external=getattr(net, "router:external", False),
                        port_security_enabled=getattr(
                            net, "port_security_enabled", True
                        ),
                        subnets=getattr(net, "subnet_ids", []),
                        project_id=getattr(net, "project_id", ""),
                        region=self.region,
                        tags=getattr(net, "tags", []),
                    )
                )
        except openstack_exceptions.SDKException as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- "  # noqa: E501
                f"Failed to list networks: {error}"
            )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- "  # noqa: E501
                f"Unexpected error listing networks: {error}"
            )

    def _list_subnets(self) -> None:
        """List all subnets."""
        logger.info("Network - Listing subnets...")
        try:
            for subnet in self.client.subnets():
                self.subnets.append(
                    Subnet(
                        id=getattr(subnet, "id", ""),
                        name=getattr(subnet, "name", ""),
                        network_id=getattr(subnet, "network_id", ""),
                        ip_version=getattr(subnet, "ip_version", 4),
                        cidr=getattr(subnet, "cidr", ""),
                        gateway_ip=getattr(subnet, "gateway_ip", None),
                        enable_dhcp=getattr(subnet, "enable_dhcp", True),
                        dns_nameservers=getattr(subnet, "dns_nameservers", []),
                        project_id=getattr(subnet, "project_id", ""),
                        region=self.region,
                    )
                )
        except openstack_exceptions.SDKException as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- "  # noqa: E501
                f"Failed to list subnets: {error}"
            )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- "  # noqa: E501
                f"Unexpected error listing subnets: {error}"
            )

    def _list_ports(self) -> None:
        """List all ports."""
        logger.info("Network - Listing ports...")
        try:
            for port in self.client.ports():
                self.ports.append(
                    Port(
                        id=getattr(port, "id", ""),
                        name=getattr(port, "name", ""),
                        network_id=getattr(port, "network_id", ""),
                        mac_address=getattr(port, "mac_address", ""),
                        fixed_ips=getattr(port, "fixed_ips", []),
                        port_security_enabled=getattr(
                            port, "port_security_enabled", True
                        ),
                        security_groups=getattr(port, "security_groups", []),
                        device_owner=getattr(port, "device_owner", ""),
                        device_id=getattr(port, "device_id", ""),
                        project_id=getattr(port, "project_id", ""),
                        region=self.region,
                    )
                )
        except openstack_exceptions.SDKException as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- "  # noqa: E501
                f"Failed to list ports: {error}"
            )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- "  # noqa: E501
                f"Unexpected error listing ports: {error}"
            )


@dataclass
class SecurityGroupRule:
    """Represents an OpenStack security group rule."""

    id: str
    security_group_id: str
    direction: str
    protocol: Optional[str]
    ethertype: str
    port_range_min: Optional[int]
    port_range_max: Optional[int]
    remote_ip_prefix: Optional[str]
    remote_group_id: Optional[str]


@dataclass
class SecurityGroup:
    """Represents an OpenStack security group."""

    id: str
    name: str
    description: str
    security_group_rules: List[SecurityGroupRule]
    project_id: str
    region: str
    is_default: bool
    tags: List[str]


@dataclass
class NetworkResource:
    """Represents an OpenStack network."""

    id: str
    name: str
    status: str
    admin_state_up: bool
    shared: bool
    external: bool
    port_security_enabled: bool
    subnets: List[str]
    project_id: str
    region: str
    tags: List[str]


@dataclass
class Subnet:
    """Represents an OpenStack subnet."""

    id: str
    name: str
    network_id: str
    ip_version: int
    cidr: str
    gateway_ip: Optional[str]
    enable_dhcp: bool
    dns_nameservers: List[str]
    project_id: str
    region: str


@dataclass
class Port:
    """Represents an OpenStack network port."""

    id: str
    name: str
    network_id: str
    mac_address: str
    fixed_ips: List[dict]
    port_security_enabled: bool
    security_groups: List[str]
    device_owner: str
    device_id: str
    project_id: str
    region: str
