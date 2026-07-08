from prowler.lib.logger import logger
from prowler.providers.scaleway.exceptions.exceptions import ScalewayAPIError


class ScalewayService:
    """Base class for Scaleway services.

    Centralizes the provider context (audit/fixer configuration, the
    scoping organization, the authenticated ``scaleway.Client``) so each
    service only worries about which Scaleway API to call.
    """

    def __init__(self, service: str, provider):
        self.provider = provider
        self.audit_config = provider.audit_config
        self.fixer_config = provider.fixer_config
        self.service = service.lower() if not service.islower() else service

        # Shared authenticated client and the organization in scope
        self.client = provider.session.client
        self.organization_id = provider.identity.organization_id

    def _safe_call(self, label: str, fn, *args, **kwargs):
        """Run a Scaleway SDK call and surface failures as ScalewayAPIError.

        Args:
            label: Human-readable label for the call (used in logs).
            fn: SDK function to invoke.

        Returns:
            The SDK function result, or ``None`` if the call failed.
        """
        try:
            return fn(*args, **kwargs)
        except Exception as error:
            logger.error(
                f"{self.service} - {label} failed: "
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            raise ScalewayAPIError(
                file=__file__,
                original_exception=error,
                message=f"Scaleway API call '{label}' failed.",
            )
