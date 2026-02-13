from concurrent.futures import ThreadPoolExecutor, as_completed

from prowler.lib.logger import logger
from prowler.providers.oraclecloud.oraclecloud_provider import OraclecloudProvider

MAX_WORKERS = 10


class OCIService:
    """
    The OCIService class offers a parent class for each OCI Service to generate:
    - OCI Regional Clients
    - Shared information like the tenancy ID, user ID, and the checks audited
    - OCI Session configuration
    - Thread pool for the __threading_call__
    - Handles compartment traversal
    """

    def __init__(self, service: str, provider: OraclecloudProvider):
        """
        Initialize the OCIService base class.

        Args:
            service (str): The OCI service name (e.g., 'compute', 'object_storage').
            provider (OraclecloudProvider): The Oracle Cloud Infrastructure provider instance.
        """
        # Audit Information
        self.provider = provider
        self.audited_tenancy = provider.identity.tenancy_id
        self.audited_user = provider.identity.user_id
        self.audited_regions = provider.regions
        self.audited_compartments = provider.compartments
        self.audited_checks = provider.audit_metadata.expected_checks
        self.audit_config = provider.audit_config
        self.fixer_config = provider.fixer_config

        # OCI Session
        self.session_config = provider.session.config
        self.session_signer = provider.session.signer

        # Service name
        self.service = service.lower() if not service.islower() else service

        # Generate Regional Clients
        self.regional_clients = provider.generate_regional_clients(self.service)

        # Thread pool for __threading_call__
        self.thread_pool = ThreadPoolExecutor(max_workers=MAX_WORKERS)

    def __get_session_config__(self):
        """Get the OCI session configuration."""
        return self.session_config

    def __get_session_signer__(self):
        """Get the OCI session signer."""
        return self.session_signer

    def __threading_call__(self, call, iterator=None):
        """
        Execute a function across multiple items using threading.

        Args:
            call (callable): The function to call for each item.
            iterator (list, optional): A list of items to process. Defaults to regional clients.
        """
        # Use the provided iterator, or default to self.regional_clients
        items = (
            iterator if iterator is not None else list(self.regional_clients.values())
        )
        # Determine the total count for logging
        item_count = len(items)

        # Trim leading and trailing underscores from the call's name
        call_name = call.__name__.strip("_")
        # Add Capitalization
        call_name = " ".join([x.capitalize() for x in call_name.split("_")])

        # Print a message based on the call's name, and if its regional or processing a list of items
        if iterator is None:
            logger.info(
                f"{self.service.upper()} - Starting threads for '{call_name}' function across {item_count} regions..."
            )
        else:
            logger.info(
                f"{self.service.upper()} - Starting threads for '{call_name}' function to process {item_count} items..."
            )

        # Submit tasks to the thread pool
        futures = [self.thread_pool.submit(call, item) for item in items]

        # Wait for all tasks to complete
        for future in as_completed(futures):
            try:
                future.result()  # Raises exceptions from the thread, if any
            except Exception as error:
                logger.error(
                    f"{self.service.upper()} - Error in threaded execution: {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def __threading_call_by_compartment__(self, call):
        """
        Execute a function for each compartment using threading.

        Args:
            call (callable): The function to call for each compartment.
                            The function should accept a compartment object.
        """
        # Use compartments as the iterator
        compartments = self.audited_compartments
        compartment_count = len(compartments)

        # Trim leading and trailing underscores from the call's name
        call_name = call.__name__.strip("_")
        # Add Capitalization
        call_name = " ".join([x.capitalize() for x in call_name.split("_")])

        logger.info(
            f"{self.service.upper()} - Starting threads for '{call_name}' function across {compartment_count} compartments..."
        )

        # Submit tasks to the thread pool
        futures = [
            self.thread_pool.submit(call, compartment) for compartment in compartments
        ]

        # Wait for all tasks to complete
        for future in as_completed(futures):
            try:
                future.result()  # Raises exceptions from the thread, if any
            except Exception as error:
                logger.error(
                    f"{self.service.upper()} - Error in compartment threaded execution: {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def __threading_call_by_region_and_compartment__(self, call):
        """
        Execute a function for each region and compartment combination using threading.

        Args:
            call (callable): The function to call for each (region, compartment) pair.
                            The function should accept region and compartment as parameters.
        """
        # Create combinations of regions and compartments
        region_compartment_pairs = [
            (region, compartment)
            for region in self.audited_regions
            for compartment in self.audited_compartments
        ]

        pair_count = len(region_compartment_pairs)

        # Trim leading and trailing underscores from the call's name
        call_name = call.__name__.strip("_")
        # Add Capitalization
        call_name = " ".join([x.capitalize() for x in call_name.split("_")])

        logger.info(
            f"{self.service.upper()} - Starting threads for '{call_name}' function across {pair_count} region-compartment pairs..."
        )

        # Submit tasks to the thread pool
        futures = [
            self.thread_pool.submit(call, region, compartment)
            for region, compartment in region_compartment_pairs
        ]

        # Wait for all tasks to complete
        for future in as_completed(futures):
            try:
                future.result()  # Raises exceptions from the thread, if any
            except Exception as error:
                logger.error(
                    f"{self.service.upper()} - Error in region-compartment threaded execution: {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def get_client_for_region(self, region_key: str):
        """
        Get the OCI service client for a specific region.

        Args:
            region_key (str): The region key (e.g., 'us-ashburn-1').

        Returns:
            The OCI service client for the region, or None if not found.
        """
        return self.regional_clients.get(region_key)

    def _create_oci_client(self, client_class, config_overrides=None, **kwargs):
        """
        Create an OCI SDK client with proper authentication handling.

        Args:
            client_class: The OCI SDK client class to instantiate
            config_overrides: Optional dict to merge with session_config (e.g., {"region": "us-ashburn-1"})
            **kwargs: Additional arguments to pass to the client constructor

        Returns:
            An instance of the OCI SDK client

        This helper method handles the different authentication methods:
        - API Key: signer is None, SDK uses key_file from config
        - Session Token: signer is SecurityTokenSigner
        - Instance Principal: signer is InstancePrincipalsSecurityTokenSigner
        """
        # Merge config overrides if provided
        config = {**self.session_config, **(config_overrides or {})}

        # Only pass signer if it's not None
        # For API key auth, signer is None and the SDK uses the key from config
        if self.session_signer:
            return client_class(config=config, signer=self.session_signer, **kwargs)
        else:
            return client_class(config=config, **kwargs)
