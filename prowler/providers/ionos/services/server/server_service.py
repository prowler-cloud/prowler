from typing import Optional, List
import ionoscloud
from ionoscloud import ApiClient, Configuration
from ionoscloud.api import ServersApi, NetworkInterfacesApi, VolumesApi, SnapshotsApi
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
        self.datacenter_id = provider.identity.datacenter_id
        self.servers = []

        self.__get_server_resources__()

    def __get_server_resources__(self):
        """
        Get all server resources from IONOS Cloud
        """
        logger.info("Getting IONOS server resources...")

        self.__get_servers_for_datacenter__(self.datacenter_id)

    def __get_servers_for_datacenter__(self, datacenter_id: str):
        """
        Get all servers for a specific datacenter
        
        Args:
            datacenter_id: ID of the datacenter to get servers from
        """
        logger.info(f"Getting servers for datacenter {datacenter_id}")
        try:
            self.servers = self.client.datacenters_servers_get(datacenter_id)
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

    def get_nics_for_server(self, server_id: str) -> Optional[list]:
        """
        Get network interfaces (NICs) for a specific server
        
        Args:
            datacenter_id: ID of the datacenter containing the server
            server_id: ID of the server
            
        Returns:
            list: List of NICs or None if not found
        """
        try:
            nics = self.network_client.datacenters_servers_nics_get(self.datacenter_id, server_id, pretty=True, depth=1)
            return nics.items if hasattr(nics, 'items') else None
        except Exception as error:
            logger.error(
                f"{datacenter_id} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return None


    def get_all_volumes(self) -> Optional[list]:
        """
        Get all volumes for all servers
        
        Returns:
            list: List of volumes or None if not found
        """
        try:
            volumes = self.client.datacenters_servers_volumes_get(self.datacenter_id, pretty=True, depth=1)
            return volumes.items if hasattr(volumes, 'items') else None
        except Exception as error:
            logger.error(
                f"{self.datacenter_id} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return None

    def get_volumes_for_server(self, server_id: str) -> Optional[list]:
        """
        Get volumes for a specific server
        
        Args:
            datacenter_id: ID of the datacenter containing the server
            server_id: ID of the server
            
        Returns:
            list: List of volumes or None if not found
        """
        try:
            volumes = self.client.datacenters_servers_volumes_get(self.datacenter_id, server_id, pretty=True, depth=1)
            return volumes.items if hasattr(volumes, 'items') else None
        except Exception as error:
            logger.error(
                f"{self.datacenter_id} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return None

    def get_snapshots_for_volume(self, volume_id: str) -> Optional[list]:
        """
        Get snapshots for a specific volume
        
        Args:
            datacenter_id: ID of the datacenter containing the volume
            volume_id: ID of the volume
            
        Returns:
            list: List of snapshots or None if not found
        """
        try:
            snapshots = self.client.datacenters_servers_volumes_snapshots_get(self.datacenter_id, volume_id, pretty=True, depth=1)
            return snapshots.items if hasattr(snapshots, 'items') else None
        except Exception as error:
            logger.error(
                f"{self.datacenter_id} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return None

    def get_all_snapshots(self) -> Optional[list]:
        """
        Get all snapshots for all volumes
        
        Returns:
            list: List of snapshots or None if not found
        """
        try:
            snapshots = self.snapshots_client.snapshots_get(pretty=True, depth=1)
            return snapshots.items if hasattr(snapshots, 'items') else None
        except Exception as error:
            logger.error(
                f"{self.datacenter_id} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return None