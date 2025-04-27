"""IONOS Base Service Module for Prowler."""

import threading
from typing import Optional, List, Dict, Any

from ionoscloud import ApiClient, Configuration
from ionoscloud.api import ServersApi, NetworkInterfacesApi
from prowler.providers.ionos.ionos_provider import IonosProvider
from prowler.lib.logger import logger

class IonosService:
    """
    This is the base class for all IONOS services.
    It provides common functionality.
    """

    def __init__(self, provider: IonosProvider):
        """
        Initialize the IonosService class.
        
        Args:
            provider: IonosProvider instance.
        """
        self.provider = provider
        self.session = self.provider.session
        self.audited_partition = "ionos"