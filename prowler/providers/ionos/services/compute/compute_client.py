import json
import logging
from typing import Optional, List, Dict, Any

import ionoscloud
from ionoscloud.api_client import ApiClient
from ionoscloud.apis.servers_api import ServersApi
from ionoscloud.apis.datacenters_api import DatacentersApi

from prowler.lib.logger import logger


class IonosComputeClient:
    def __init__(self, session_client: ApiClient):
        """
        Initialize IonosComputeClient with an IONOS API session client.
        
        Args:
            session_client: ApiClient object to interact with IONOS API
        """
        self.session = session_client
        self.servers_api = ServersApi(self.session)
        self.datacenters_api = DatacentersApi(self.session)
        self.datacenters = None
        self.servers = {}
        self.region = None
        self.logger = logger

    def get_datacenters(self) -> List[Dict[str, Any]]:
        """
        Get all datacenters from IONOS Cloud.
        
        Returns:
            List of datacenter dictionaries
        """
        try:
            if not self.datacenters:
                response = self.datacenters_api.datacenters_get(depth=1)
                self.datacenters = response.items
            return self.datacenters
        except Exception as error:
            self.logger.error(f"Error getting IONOS datacenters: {error}")
            return []

    def get_servers(self, datacenter_id: str) -> List[Dict[str, Any]]:
        """
        Get all servers for a specific datacenter.
        
        Args:
            datacenter_id: ID of the datacenter to list servers from
            
        Returns:
            List of server dictionaries
        """
        try:
            if datacenter_id not in self.servers:
                response = self.servers_api.datacenters_servers_get(datacenter_id=datacenter_id, depth=2)
                self.servers[datacenter_id] = response.items
            return self.servers[datacenter_id]
        except Exception as error:
            self.logger.error(f"Error getting servers for datacenter {datacenter_id}: {error}")
            return []

    def get_all_servers(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Get all servers from all datacenters.
        
        Returns:
            Dictionary mapping datacenter IDs to lists of server dictionaries
        """
        all_servers = {}
        try:
            datacenters = self.get_datacenters()
            for datacenter in datacenters:
                datacenter_id = datacenter.id
                servers = self.get_servers(datacenter_id)
                all_servers[datacenter_id] = servers
        except Exception as error:
            self.logger.error(f"Error getting all IONOS servers: {error}")
        
        return all_servers

    def get_server_details(self, datacenter_id: str, server_id: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed information about a specific server.
        
        Args:
            datacenter_id: ID of the datacenter containing the server
            server_id: ID of the server to get details for
            
        Returns:
            Dictionary containing server details or None if an error occurs
        """
        try:
            response = self.servers_api.datacenters_servers_find_by_id(
                datacenter_id=datacenter_id, 
                server_id=server_id, 
                depth=3
            )
            return response
        except Exception as error:
            self.logger.error(f"Error getting details for server {server_id} in datacenter {datacenter_id}: {error}")
            return None

