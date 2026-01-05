from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict

from prowler.lib.logger import logger

MAX_WORKERS = 10


class AlibabaCloudService:
    """
    The AlibabaCloudService class offers a parent class for each Alibaba Cloud Service to generate:
    - Alibaba Cloud Regional Clients
    - Shared information like the account ID, the checks audited
    - Thread pool for the __threading_call__
    - Handles if the service is Regional or Global
    """

    def __init__(self, service: str, provider, global_service: bool = False):
        """
        Initialize the AlibabaCloudService.

        Args:
            service: The service name (e.g., 'RAM', 'ECS', 'OSS')
            provider: The AlibabaCloudProvider instance
            global_service: Whether this is a global service (default: False)
        """
        # Audit Information
        self.provider = provider
        self.audited_account = provider.identity.account_id
        self.audited_account_name = provider.identity.account_name
        self.audit_resources = provider.audit_resources
        self.audited_checks = provider.audit_metadata.expected_checks
        self.audit_config = provider.audit_config

        # Session
        self.session = provider.session

        # Service name
        self.service = service.lower() if not service.islower() else service

        # Generate Regional Clients
        self.regional_clients: Dict[str, Any] = {}
        if not global_service:
            self.regional_clients = provider.generate_regional_clients(self.service)

        # Get default region and client
        self.region = provider.get_default_region(self.service)
        self.client = self.session.client(self.service, self.region)

        # Thread pool for __threading_call__
        self.thread_pool = ThreadPoolExecutor(max_workers=MAX_WORKERS)

    def __get_session__(self):
        """Get the session."""
        return self.session

    def __get_client__(self, region: str = None):
        """
        Get a client for the specified region or the default region.

        Args:
            region: The region to get the client for (optional)

        Returns:
            A client instance for the service
        """
        if region and region in self.regional_clients:
            return self.regional_clients[region]
        return self.client

    def __threading_call__(self, call, iterator=None):
        """
        Execute a function across multiple regions or items using threads.

        Args:
            call: The function to call
            iterator: The items to iterate over (default: regional clients)
        """
        # Use the provided iterator, or default to self.regional_clients
        items = iterator if iterator is not None else self.regional_clients.values()
        # Determine the total count for logging
        item_count = (
            len(list(items)) if iterator is not None else len(self.regional_clients)
        )

        # Trim leading and trailing underscores from the call's name
        call_name = call.__name__.strip("_")
        # Add Capitalization
        call_name = " ".join([x.capitalize() for x in call_name.split("_")])

        # Print a message based on the call's name
        if iterator is None:
            logger.info(
                f"{self.service.upper()} - Starting threads for '{call_name}' function across {item_count} regions..."
            )
        else:
            logger.info(
                f"{self.service.upper()} - Starting threads for '{call_name}' function to process {item_count} items..."
            )

        # Re-create the iterator for submission if it was a generator
        items = iterator if iterator is not None else self.regional_clients.values()

        # Submit tasks to the thread pool
        futures = [self.thread_pool.submit(call, item) for item in items]

        # Wait for all tasks to complete
        for future in as_completed(futures):
            try:
                future.result()  # Raises exceptions from the thread, if any
            except Exception:
                # Handle exceptions if necessary
                pass  # Currently handled within the called function
