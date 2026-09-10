from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from prowler.lib.logger import logger
from prowler.providers.googleworkspace.googleworkspace_provider import (
    GoogleworkspaceProvider,
)

# How far a Cloud Identity policy reaches.
CUSTOMER_SCOPE = "customer"
OVERRIDE_SCOPE = "override"
UNKNOWN_SCOPE = "unknown"


class GoogleWorkspaceService:
    def __init__(
        self,
        provider: GoogleworkspaceProvider,
    ):
        self.provider = provider
        self.domain_resource = provider.domain_resource
        self.audit_config = provider.audit_config
        self.fixer_config = provider.fixer_config
        self.credentials = provider.session.credentials

    def _build_service(self, api_name: str, api_version: str):
        """
        Build and return a Google API service client.

        Args:
            api_name: The name of the API (e.g., 'admin')
            api_version: The API version (e.g., 'directory_v1')

        Returns:
            A Google API service client
        """
        try:
            return build(
                api_name,
                api_version,
                credentials=self.credentials,
                cache_discovery=False,
            )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return None

    def _policy_scope(self, policy: dict) -> str:
        """Return how far a policy reaches: CUSTOMER_SCOPE, OVERRIDE_SCOPE or UNKNOWN_SCOPE.

        The Cloud Identity Policy API typically scopes every policy to an OU,
        and the root OU is equivalent to customer-level, so telling them apart
        needs the root OU id. That id is fetched on a best-effort basis, and
        without it a root-OU policy is indistinguishable from a sub-OU one:
        that is UNKNOWN_SCOPE, which callers must not read as either.
        """
        policy_query = policy.get("policyQuery") or {}
        if policy_query.get("group"):
            return OVERRIDE_SCOPE
        org_unit = policy_query.get("orgUnit")
        if not org_unit:
            return CUSTOMER_SCOPE
        root_id = getattr(self.provider.identity, "root_org_unit_id", None)
        if not root_id:
            return UNKNOWN_SCOPE
        return CUSTOMER_SCOPE if org_unit == f"orgUnits/{root_id}" else OVERRIDE_SCOPE

    def _is_customer_level_policy(self, policy: dict) -> bool:
        """Whether a policy applies to the whole domain."""
        return self._policy_scope(policy) == CUSTOMER_SCOPE

    def _handle_api_error(self, error, context: str, resource_name: str = ""):
        """
        Centralized Google Workspace API error handling.

        Args:
            error: The exception that was raised
            context: Description of what operation was being performed
            resource_name: Name of the resource being accessed (optional)
        """
        resource_info = resource_name if resource_name else ""

        if isinstance(error, HttpError):
            if error.resp.status == 403:
                logger.error(
                    f"Access denied while {context} {resource_info}: Insufficient permissions or API not enabled"
                )
            elif error.resp.status == 404:
                logger.error(f"{resource_info} not found while {context}")
            elif error.resp.status == 429:
                logger.error(
                    f"Rate limit exceeded while {context} {resource_info}: {error}"
                )
            elif error.resp.status == 401:
                logger.error(
                    f"Authentication error while {context} {resource_info}: Check credentials and delegation"
                )
            else:
                logger.error(
                    f"Google API error ({error.resp.status}) while {context} {resource_info}: {error}"
                )
        else:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] while {context} {resource_info}: {error}"
            )
