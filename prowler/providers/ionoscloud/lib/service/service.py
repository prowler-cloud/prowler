from concurrent.futures import ThreadPoolExecutor, as_completed

from prowler.lib.logger import logger

MAX_WORKERS = 10


class IonosCloudService:
    """
    Base service class for all IONOS Cloud services.

    Provides:
    - Shared provider and identity information
    - A thread pool for concurrent API calls
    - The configured ApiClient for SDK calls
    """

    def __init__(self, service: str, provider):
        self.provider = provider
        self.audited_account = provider.identity.user_email
        self.audit_resources = provider.audit_resources
        self.audited_checks = provider.audit_metadata.expected_checks
        self.audit_config = provider.audit_config
        self.service = service
        self.api_client = provider.session
        self.thread_pool = ThreadPoolExecutor(max_workers=MAX_WORKERS)

    def __threading_call__(self, call, iterator=None):
        """Execute a function over a list of items concurrently."""
        items = list(iterator) if iterator is not None else []
        call_name = " ".join(
            x.capitalize() for x in call.__name__.strip("_").split("_")
        )
        logger.info(
            f"{self.service.upper()} - Starting threads for '{call_name}' "
            f"to process {len(items)} items..."
        )
        futures = [self.thread_pool.submit(call, item) for item in items]
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as error:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
