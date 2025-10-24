"""
Alibaba Cloud Service Base Class

This module provides the base class for all Alibaba Cloud service implementations.
"""

import threading
from typing import Any, Dict, List

from prowler.lib.logger import logger


class AlibabaCloudService:
    """
    Base class for Alibaba Cloud service implementations

    This class provides common functionality for all Alibaba Cloud services, including:
    - Regional client management
    - Multi-threading support for API calls
    - Error handling patterns
    - Resource auditing metadata

    Attributes:
        provider: The Alibaba Cloud provider instance
        service: Service name (e.g., "ecs", "oss", "ram")
        account_id: Alibaba Cloud account ID
        regions: List of regions to audit
        audit_config: Audit configuration dictionary
        regional_clients: Dictionary of regional SDK clients
    """

    def __init__(self, service: str, provider):
        """
        Initialize the Alibaba Cloud service

        Args:
            service: Service identifier (e.g., "ecs", "oss")
            provider: AlibabaCloudProvider instance
        """
        self.provider = provider
        self.service = service
        self.account_id = provider.identity.account_id
        self.regions = provider._regions
        self.audit_config = provider.audit_config
        self.regional_clients = {}

        logger.info(f"Initializing Alibaba Cloud {service.upper()} service")

    def __threading_call__(self, call, iterator):
        """
        Execute function calls in parallel using threading

        This method is used to parallelize API calls across regions or resources
        to improve audit performance.

        Args:
            call: Function to execute
            iterator: Iterable of arguments to pass to the function

        Example:
            self.__threading_call__(self._describe_instances, self.regions)
        """
        threads = []
        for item in iterator:
            thread = threading.Thread(target=call, args=(item,))
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

    def _create_regional_client(self, region: str, endpoint_override: str = None):
        """
        Create a regional Alibaba Cloud SDK client

        This method should be overridden by service implementations to create
        service-specific clients.

        Args:
            region: Region identifier
            endpoint_override: Optional endpoint override URL

        Returns:
            SDK client instance for the specified region
        """
        raise NotImplementedError(
            f"Service {self.service} must implement _create_regional_client()"
        )

    def _list_resources(self):
        """
        List all resources for this service

        This method should be overridden by service implementations to list
        service-specific resources.
        """
        raise NotImplementedError(
            f"Service {self.service} must implement _list_resources()"
        )

    def _get_resource_details(self, resource):
        """
        Get detailed information about a resource

        This method can be overridden by service implementations to fetch
        additional resource details.

        Args:
            resource: Resource identifier or object
        """
        pass

    def _handle_api_error(self, error: Exception, operation: str, region: str = None):
        """
        Handle Alibaba Cloud API errors with consistent logging

        Args:
            error: The exception that occurred
            operation: The API operation that failed
            region: The region where the error occurred (if applicable)
        """
        region_info = f" in region {region}" if region else ""
        logger.warning(
            f"{self.service.upper()} {operation} failed{region_info}: {str(error)}"
        )

    def generate_resource_arn(
        self, resource_type: str, resource_id: str, region: str = ""
    ) -> str:
        """
        Generate Alibaba Cloud Resource Name (ARN) in ACS format

        Format: acs:{service}:{region}:{account-id}:{resource-type}/{resource-id}

        Args:
            resource_type: Type of resource (e.g., "instance", "bucket")
            resource_id: Resource identifier
            region: Region identifier (optional for global resources)

        Returns:
            str: Formatted ARN string

        Example:
            arn = self.generate_resource_arn("instance", "i-abc123", "cn-hangzhou")
            # Returns: "acs:ecs:cn-hangzhou:123456789:instance/i-abc123"
        """
        return f"acs:{self.service}:{region}:{self.account_id}:{resource_type}/{resource_id}"
