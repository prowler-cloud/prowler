import os
from concurrent.futures import ThreadPoolExecutor, as_completed

from prowler.lib.logger import logger
from prowler.providers.linode.exceptions.exceptions import LinodeMissingPermissionError
from prowler.providers.linode.linode_provider import LinodeProvider

MAX_WORKERS = 10


class LinodeService:
    """Base class for Linode services to share provider context."""

    def __init__(self, service: str, provider: LinodeProvider):
        """
        Initialize the Linode service with provider context.

        Args:
            service: The Linode service name (e.g., administration, compute, networking).
            provider: LinodeProvider instance containing session, audit config, and fixer config.
        """
        self.provider = provider
        self.client = provider.session.client
        self.audit_config = provider.audit_config
        self.fixer_config = provider.fixer_config
        self.service = service.lower() if not service.islower() else service

        self.thread_pool = ThreadPoolExecutor(max_workers=MAX_WORKERS)

    def _log_fetch_error(
        self, resource_label: str, required_scope: str, error: Exception
    ) -> None:
        """Log a resource-fetch failure, distinguishing an insufficient-scope
        (HTTP 401/403) error from a generic API error.

        This never raises: a single service's missing permission must not abort
        the rest of the scan. When the token lacks the required scope, the log
        names the exact scope to grant via ``LinodeMissingPermissionError``.

        Args:
            resource_label: Human-readable resource name (e.g. "firewalls").
            required_scope: The Linode OAuth scope needed (e.g. "firewall:read_only").
            error: The exception raised by the SDK call.
        """
        service_name = getattr(self, "service", "linode")
        status = getattr(error, "status", None)
        if status in (401, 403) or "not authorized to use this endpoint" in str(error):
            logger.error(
                str(
                    LinodeMissingPermissionError(
                        file=os.path.basename(__file__),
                        message=(
                            f"{service_name} - unable to list {resource_label}: the Linode "
                            f"token lacks the '{required_scope}' scope; skipping these checks."
                        ),
                        original_exception=error,
                    )
                )
            )
        else:
            logger.error(
                f"{service_name} - Error fetching {resource_label}: "
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

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
