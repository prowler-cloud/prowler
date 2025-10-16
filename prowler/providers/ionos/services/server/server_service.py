from typing import List, Optional

from ionoscloud.api import (
    FirewallRulesApi,
    NetworkInterfacesApi,
    ServersApi,
    SnapshotsApi,
)

from prowler.lib.logger import logger
from prowler.providers.ionos.lib.service import IonosService


class IonosServer(IonosService):
    """
    IonosServer is the class for handling server resources in IONOS Cloud.
    """

    def __init__(self, provider):
        """
        Initialize IonosServer class.

        Args:
            provider: IonosProvider instance with authenticated API client
        """
        logger.info("Initializing IONOS Server service")
        super().__init__(provider)
        self.service = "server"
        self.client = ServersApi(self.session)
        self.network_client = NetworkInterfacesApi(self.session)
        self.snapshots_client = SnapshotsApi(self.session)
        self.security_rules_api = FirewallRulesApi(self.session)
        self.datacenter_id = provider.identity.datacenter_id
        self.servers: List = []

        self.__get_server_resources__()

    def __get_server_resources__(self) -> None:
        """
        Get all server resources from IONOS Cloud.
        """
        logger.info("Getting IONOS server resources...")
        self.__get_servers_for_datacenter__(self.datacenter_id)

    def __get_servers_for_datacenter__(self, datacenter_id: str) -> None:
        """
        Get all servers for a specific datacenter.

        Args:
            datacenter_id: ID of the datacenter to get servers from
        """
        logger.info("Getting servers for datacenter %s", datacenter_id)
        try:
            self.servers = self.client.datacenters_servers_get(
                datacenter_id,
                pretty=True,
                depth=1,
            )
        except Exception as error:
            logger.error(
                "%s -- %s[%s]: %s",
                datacenter_id,
                error.__class__.__name__,
                error.__traceback__.tb_lineno,
                error,
            )

    def get_all_servers(self) -> List:
        """
        Get all servers from the cached datacenter.

        Returns:
            list: List of server resources
        """
        return getattr(self.servers, "items", self.servers)

    def get_server_by_id(self, server_id: str) -> Optional[dict]:
        """
        Get server details by server ID.

        Args:
            server_id: ID of the server to get

        Returns:
            dict: Server details or None if not found
        """
        for server in self.get_all_servers() or []:
            if getattr(server, "id", None) == server_id:
                return server
        return None

    def get_server_status(self, datacenter_id: str, server_id: str) -> Optional[str]:
        """
        Get the status of a specific server.

        Args:
            datacenter_id: ID of the datacenter containing the server
            server_id: ID of the server

        Returns:
            str: Status of the server or None if not found
        """
        try:
            server = self.client.get_server_details(datacenter_id, server_id)
            return getattr(server.properties, "vm_state", None)
        except Exception as error:
            logger.error(
                "%s -- %s[%s]: %s",
                datacenter_id,
                error.__class__.__name__,
                error.__traceback__.tb_lineno,
                error,
            )
            return None

    def get_nics_for_server(self, server_id: str) -> Optional[List]:
        """
        Get network interfaces (NICs) for a specific server.

        Args:
            server_id: ID of the server

        Returns:
            list: List of NICs or None if not found
        """
        try:
            nics = self.network_client.datacenters_servers_nics_get(
                self.datacenter_id,
                server_id,
                pretty=True,
                depth=1,
            )
            return getattr(nics, "items", None)
        except Exception as error:
            logger.error(
                "%s -- %s[%s]: %s",
                self.datacenter_id,
                error.__class__.__name__,
                error.__traceback__.tb_lineno,
                error,
            )
            return None

    def get_all_volumes(self) -> Optional[List]:
        """
        Get all volumes for all servers in the cached datacenter.

        Returns:
            list: List of volumes or None if not found
        """
        try:
            volumes = self.client.datacenters_servers_volumes_get(
                self.datacenter_id,
                pretty=True,
                depth=1,
            )
            return getattr(volumes, "items", None)
        except Exception as error:
            logger.error(
                "%s -- %s[%s]: %s",
                self.datacenter_id,
                error.__class__.__name__,
                error.__traceback__.tb_lineno,
                error,
            )
            return None

    def get_volumes_for_server(self, server_id: str) -> Optional[List]:
        """
        Get volumes for a specific server.

        Args:
            server_id: ID of the server

        Returns:
            list: List of volumes or None if not found
        """
        try:
            volumes = self.client.datacenters_servers_volumes_get(
                self.datacenter_id,
                server_id,
                pretty=True,
                depth=1,
            )
            return getattr(volumes, "items", None)
        except Exception as error:
            logger.error(
                "%s -- %s[%s]: %s",
                self.datacenter_id,
                error.__class__.__name__,
                error.__traceback__.tb_lineno,
                error,
            )
            return None

    def get_snapshots_for_volume(self, volume_id: str) -> Optional[List]:
        """
        Get snapshots for a specific volume.

        Args:
            volume_id: ID of the volume

        Returns:
            list: List of snapshots or None if not found
        """
        try:
            snapshots = self.client.datacenters_servers_volumes_snapshots_get(
                self.datacenter_id,
                volume_id,
                pretty=True,
                depth=1,
            )
            return getattr(snapshots, "items", None)
        except Exception as error:
            logger.error(
                "%s -- %s[%s]: %s",
                self.datacenter_id,
                error.__class__.__name__,
                error.__traceback__.tb_lineno,
                error,
            )
            return None

    def get_all_snapshots(self) -> Optional[List]:
        """
        Get all snapshots for all volumes.

        Returns:
            list: List of snapshots or None if not found
        """
        try:
            snapshots = self.snapshots_client.snapshots_get(pretty=True, depth=1)
            return getattr(snapshots, "items", None)
        except Exception as error:
            logger.error(
                "%s -- %s[%s]: %s",
                self.datacenter_id,
                error.__class__.__name__,
                error.__traceback__.tb_lineno,
                error,
            )
            return None

    def get_network_security_rules(self, server_id: str, nic_id: str) -> Optional[List]:
        """
        Get all network security rules for a server NIC.

        Returns:
            list: List of firewall rules or None if not found
        """
        try:
            logger.info(
                "Fetching firewall rules for server %s and NIC %s",
                server_id,
                nic_id,
            )
            firewall_rules = (
                self.security_rules_api.datacenters_servers_nics_firewallrules_get(
                    self.datacenter_id,
                    server_id,
                    nic_id,
                    pretty=True,
                    depth=1,
                )
            )
            return getattr(firewall_rules, "items", None)
        except Exception as error:
            logger.error(
                "%s -- %s[%s]: %s",
                self.datacenter_id,
                error.__class__.__name__,
                error.__traceback__.tb_lineno,
                error,
            )
            return None
