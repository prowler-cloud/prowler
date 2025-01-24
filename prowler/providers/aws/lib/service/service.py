from concurrent.futures import ThreadPoolExecutor, as_completed

from prowler.lib.logger import logger
from prowler.providers.aws.aws_provider import AwsProvider

# TODO: review the following code
# from prowler.providers.aws.aws_provider import (
#     generate_regional_clients,
#     get_default_region,
# )

MAX_WORKERS = 10


class AWSService:
    """The AWSService class offers a parent class for each AWS Service to generate:
    - AWS Regional Clients
    - Shared information like the account ID and ARN, the AWS partition and the checks audited
    - AWS Session
    - Thread pool for the __threading_call__
    - Also handles if the AWS Service is Global
    """

    failed_checks = set()

    @classmethod
    def set_failed_check(cls, check_id=None, arn=None):
        if check_id is not None and arn is not None:
            cls.failed_checks.add((check_id.split(".")[-1], arn))

    @classmethod
    def is_failed_check(cls, check_id, arn):
        return (check_id.split(".")[-1], arn) in cls.failed_checks

    def __init__(self, service: str, provider: AwsProvider, global_service=False):
        # Audit Information
        # Do we need to store the whole provider?
        self.provider = provider
        self.audited_account = provider.identity.account
        self.audited_account_arn = provider.identity.account_arn
        self.audited_partition = provider.identity.partition
        self.audit_resources = provider.audit_resources
        # TODO: remove this
        self.audited_checks = provider.audit_metadata.expected_checks
        self.audit_config = provider.audit_config
        self.fixer_config = provider.fixer_config

        # AWS Session
        self.session = provider.session.current_session

        # We receive the service using __class__.__name__ or the service name in lowercase
        # e.g.: AccessAnalyzer --> we need a lowercase string, so service.lower()
        self.service = service.lower() if not service.islower() else service

        # Generate Regional Clients
        if not global_service:
            self.regional_clients = provider.generate_regional_clients(self.service)
            # TODO: review the following code
            # self.regional_clients = generate_regional_clients(self.service, audit_info)

        # Get a single region and client if the service needs it (e.g. AWS Global Service)
        # We cannot include this within an else because some services needs both the regional_clients
        # and a single client like S3
        self.region = provider.get_default_region(self.service)
        self.client = self.session.client(self.service, self.region)

        # Thread pool for __threading_call__
        self.thread_pool = ThreadPoolExecutor(max_workers=MAX_WORKERS)

    def __get_session__(self):
        return self.session

    def __threading_call__(self, call, iterator=None):
        # Use the provided iterator, or default to self.regional_clients
        items = iterator if iterator is not None else self.regional_clients.values()
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
            except Exception:
                # Handle exceptions if necessary
                pass  # Replace 'pass' with any additional exception handling logic. Currently handled within the called function

    def get_unknown_arn(self, resource_type: str = None, region: str = None) -> str:
        """
        Generate an unknown ARN for the service
        Args:
            region (str): The region to get the unknown ARN for.
            resource_type (str): The resource type to get the unknown ARN for
        Returns:
            str: The unknown ARN for the region.
        Examples:
            >>> service.get_unknown_arn(resource_type="bucket", region="us-east-1")
            arn:aws:s3:us-east-1:123456789012:bucket/unknown
        """
        return f"arn:{self.audited_partition}:{self.service}:{f'{region}' if region else ''}:{self.audited_account}:{f'{resource_type}/' if resource_type else ''}unknown"
