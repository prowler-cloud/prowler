from typing import Optional, List
import ionoscloud
from ionoscloud import ApiClient, Configuration
from ionoscloud.services import ServersApi
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
        self.service = "server"
        self.session = provider.session
        self.client = ServersApi(provider.session)
        self.datacenter_id = provider.identity.datacenter_id
        self.servers = []
        self.__threading_call__(self.__get_server_resources__)

    def __get_server_resources__(self):
        """
        Get all server resources from IONOS Cloud
        """
        logger.info("Getting IONOS server resources...")

        self.__get_servers_for_datacenter__(datacenter.id)

    def __get_servers_for_datacenter__(self, datacenter_id: str):
        """
        Get all servers for a specific datacenter
        
        Args:
            datacenter_id: ID of the datacenter to get servers from
        """
        logger.info(f"Getting servers for datacenter {datacenter_id}")
        try:
            self.servers = self.client.datacenters_servers_get(datacenter_id)
            #for server in servers:
            #    server_details = self.client.get_server_details(datacenter_id, server.id)
            #    self.servers.append(server_details)
        except Exception as error:
            logger.error(
                f"{datacenter_id} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def get_all_servers(self) -> list:
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

    def get_server_status(self, datacenter_id: str, server_id: str) -> Optional[str]:
        """
        Get the status of a specific server
        
        Args:
            datacenter_id: ID of the datacenter containing the server
            server_id: ID of the server
            
        Returns:
            str: Status of the server or None if not found
        """
        try:
            server = self.client.get_server_details(datacenter_id, server_id)
            return server.properties.vm_state
        except Exception as error:
            logger.error(
                f"{datacenter_id} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return None
