"""IONOS Base Service Module for Prowler."""

import threading
from typing import Optional, List, Dict, Any

from prowler.providers.ionos.ionos_provider import IonosProvider


class IonosService:
    """
    This is the base class for all IONOS services.
    It provides common functionality like threading and region handling.
    """

    def __init__(self, provider: IonosProvider):
        """
        Initialize the IonosService class.
        
        Args:
            provider: IonosProvider instance.
        """
        self.provider = provider
        self.client = None
        self.region = None
        self.session = None
        self.audited_account = provider.audited_account
        self.audit_info = provider.audit_info
        self.audited_partition = "ionos"
        self.lock = threading.Lock()
        
        # Set common audit resources
        self.audited_resources = []
    
    def _init_client(self, client_class, **kwargs):
        """
        Initialize a client using the provider's session.
        
        Args:
            client_class: Class of the client to initialize.
            **kwargs: Additional arguments to pass to the client constructor.
        """
        return client_class(self.provider.session, **kwargs)
    
    def _regional_operation(self, regions: List[str], operation, **kwargs) -> Dict[str, Any]:
        """
        Execute an operation across multiple regions if IONOS supports regions.
        
        Args:
            regions: List of regions to operate on.
            operation: Function to execute in each region.
            **kwargs: Additional arguments to pass to the operation.
        
        Returns:
            Dictionary with results per region.
        """
        results = {}
        for region in regions:
            self.region = region
            results[region] = operation(region=region, **kwargs)
        return results
    
    def _threaded_operation(self, targets: List[Any], operation, **kwargs) -> List[Any]:
        """
        Execute an operation in parallel threads.
        
        Args:
            targets: List of targets to operate on.
            operation: Function to execute for each target.
            **kwargs: Additional arguments to pass to the operation.
        
        Returns:
            List of results.
        """
        threads = []
        results = []
        
        for target in targets:
            thread = threading.Thread(
                target=lambda item, results: results.append(operation(item, **kwargs)),
                args=(target, results),
            )
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
            
        return results
    
    def _get_resource_arn(self, resource_type: str, resource_id: str) -> str:
        """
        Generate an ARN-like identifier for IONOS resources.
        
        Args:
            resource_type: Type of the resource.
            resource_id: ID of the resource.
        
        Returns:
            ARN-like string for the resource.
        """
        return f"ionos:{resource_type}:{self.region or 'global'}:{self.audited_account}:{resource_id}"

    def __threading_call__(self, function, *args, **kwargs):
        """
        Execute a function in a separate thread.
        
        Args:
            function: The function to execute.
            *args: Arguments to pass to the function.
            **kwargs: Keyword arguments to pass to the function.
        
        Returns:
            Result of the function call.
        """
        result = []
        thread = threading.Thread(
            target=lambda: result.append(function(*args, **kwargs))
        )
        thread.start()
        thread.join()
        
        # Return the result if there is one
        return result[0] if result else None

