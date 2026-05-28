from concurrent.futures import ThreadPoolExecutor, as_completed

from prowler.lib.logger import logger
from prowler.providers.linode.linode_provider import LinodeProvider

MAX_WORKERS = 10


class LinodeService:
    """Base class for Linode services to share provider context."""

    def __init__(self, service: str, provider: LinodeProvider):
        self.provider = provider
        self.client = provider.session.client
        self.audit_config = provider.audit_config
        self.fixer_config = provider.fixer_config
        self.service = service.lower() if not service.islower() else service

        self.thread_pool = ThreadPoolExecutor(max_workers=MAX_WORKERS)

    def __threading_call__(self, call, iterator):
        """Execute a function across multiple items using threading."""
        items = list(iterator) if not isinstance(iterator, list) else iterator

        futures = {self.thread_pool.submit(call, item): item for item in items}
        results = []

        for future in as_completed(futures):
            try:
                result = future.result()
                if result is not None:
                    results.append(result)
            except Exception as error:
                item = futures[future]
                item_id = getattr(item, "id", str(item))
                logger.error(
                    f"{self.service} - Threading error processing {item_id}: "
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

        return results
