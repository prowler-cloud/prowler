from typing import Optional, List
import ionoscloud
from prowler.lib.logger import logger
from prowler.providers.ionos.lib.service import IonosService
from prowler.providers.ionos.services.compute.compute_client import IonosComputeClient

class IonosCompute(IonosService):
    """
    IonosCompute is the class for handling compute resources (servers, datacenters) in IONOS.
    """

    def __init__(self, provider):
        """
        Initialize IonosCompute class.
        
        Args:
            provider: IonosProvider instance with authenticated API client
        """
        logger.info("Initializing IONOS Compute service")
        self.service = "compute"
        self.session = provider.session
        self.client = IonosComputeClient(provider.session)
        self.datacenters = []
        self.servers = []
        self.__threading_call__(self.__get_compute_resources__)

    def __get_compute_resources__(self):
        """
        Get all compute resources from IONOS Cloud
        """
        logger.info("Getting IONOS compute resources...")
        self.datacenters = self.client.get_datacenters()

        for datacenter in self.datacenters:
            self.__get_servers_for_datacenter__(datacenter.id)

    def __get_servers_for_datacenter__(self, datacenter_id: str):
        """
        Get all servers for a specific datacenter
        
        Args:
            datacenter_id: ID of the datacenter to get servers from
        """
        logger.info(f"Getting servers for datacenter {datacenter_id}")
        try:
            servers = self.client.get_servers(datacenter_id)
            for server in servers:
                server_details = self.client.get_server_details(datacenter_id, server.id)
                self.servers.append(server_details)
        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def get_servers(self) -> list:
        """
        Get all servers from all datacenters
        
        Returns:
            list: List of server resources
        """
        return self.servers

    def get_server_by_id(self, server_id: str) -> Optional[dict]:
        """
        Get server details by server ID
        
        Args:
            server_id: ID of the server to get
            
        Returns:
            dict: Server details or None if not found
        """
        for server in self.servers:
            if server.id == server_id:
                return server
        return None

    def get_datacenters(self) -> list:
        """
        Get all datacenters
        
        Returns:
            list: List of datacenter resources
        """
        return self.datacenters

