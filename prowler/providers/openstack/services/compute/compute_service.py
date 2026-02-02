from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

from openstack import exceptions as openstack_exceptions

from prowler.lib.logger import logger
from prowler.providers.openstack.lib.service.service import OpenStackService


class Compute(OpenStackService):
    """Service wrapper using openstacksdk compute APIs."""

    def __init__(self, provider) -> None:
        super().__init__(__class__.__name__, provider)
        self.client = self.connection.compute
        self.instances: List[ComputeInstance] = []
        self._list_instances()

    def _list_instances(self) -> None:
        """List all compute instances in the current project."""
        logger.info("Compute - Listing instances...")
        try:
            for server in self.client.servers():
                # Extract security group names (handle None case)
                sg_list = getattr(server, "security_groups", None) or []
                security_groups = [sg.get("name", "") for sg in sg_list]

                # Extract network information from addresses
                networks_dict = {}
                addresses_attr = getattr(server, "addresses", None)
                if addresses_attr:
                    for net_name, addr_list in addresses_attr.items():
                        # addr_list is a list of dicts like:
                        # [{'version': 4, 'addr': '57.128.163.151', 'OS-EXT-IPS:type': 'fixed'}]
                        ip_list = []
                        if isinstance(addr_list, list):
                            for addr_dict in addr_list:
                                if isinstance(addr_dict, dict) and "addr" in addr_dict:
                                    ip_list.append(addr_dict["addr"])
                                elif isinstance(addr_dict, str):
                                    # Fallback: if it's just a string IP
                                    ip_list.append(addr_dict)
                        elif isinstance(addr_list, str):
                            # Fallback: single string IP
                            ip_list = [addr_list]
                        networks_dict[net_name] = ip_list

                # Extract trusted image certificates
                trusted_certs = (
                    getattr(server, "trusted_image_certificates", None) or []
                )

                self.instances.append(
                    ComputeInstance(
                        # Basic instance information
                        id=getattr(server, "id", ""),
                        name=getattr(server, "name", ""),
                        status=getattr(server, "status", ""),
                        flavor_id=getattr(server, "flavor", {}).get("id", ""),
                        security_groups=security_groups,
                        region=self.region,
                        project_id=self.project_id,
                        # Access Control & Authentication
                        is_locked=getattr(server, "is_locked", False),
                        locked_reason=getattr(server, "locked_reason", ""),
                        key_name=getattr(server, "key_name", ""),
                        user_id=getattr(server, "user_id", ""),
                        # Network Exposure
                        access_ipv4=getattr(server, "access_ipv4", ""),
                        access_ipv6=getattr(server, "access_ipv6", ""),
                        public_v4=getattr(server, "public_v4", ""),
                        public_v6=getattr(server, "public_v6", ""),
                        private_v4=getattr(server, "private_v4", ""),
                        private_v6=getattr(server, "private_v6", ""),
                        networks=networks_dict,
                        # Configuration Security
                        has_config_drive=getattr(server, "has_config_drive", False),
                        metadata=getattr(server, "metadata", {}),
                        user_data=getattr(server, "user_data", ""),
                        # Image Trust
                        trusted_image_certificates=(
                            trusted_certs if isinstance(trusted_certs, list) else []
                        ),
                    )
                )
        except openstack_exceptions.SDKException as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- "
                f"Failed to list compute instances: {error}"
            )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- "
                f"Unexpected error listing compute instances: {error}"
            )


@dataclass
class ComputeInstance:
    """Represents an OpenStack compute instance (VM)."""

    # Basic instance information
    id: str
    name: str
    status: str
    flavor_id: str
    security_groups: List[str]
    region: str
    project_id: str

    # Access Control & Authentication
    is_locked: bool
    locked_reason: str
    key_name: str
    user_id: str

    # Network Exposure
    access_ipv4: str
    access_ipv6: str
    public_v4: str
    public_v6: str
    private_v4: str
    private_v6: str
    networks: Dict[str, List[str]]

    # Configuration Security
    has_config_drive: bool
    metadata: Dict[str, str]
    user_data: str

    # Image Trust
    trusted_image_certificates: List[str]
