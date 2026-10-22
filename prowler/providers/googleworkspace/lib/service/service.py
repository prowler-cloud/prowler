from typing import Optional

from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.googleworkspace.googleworkspace_provider import (
    GoogleworkspaceProvider,
)

# How far a Cloud Identity policy reaches.
CUSTOMER_SCOPE = "customer"
OVERRIDE_SCOPE = "override"
UNKNOWN_SCOPE = "unknown"

# Settings whose policies are items of a list rather than competing values for
# one setting: every rule is a distinct policy and none outranks another.
LIST_SETTING_NAMESPACES = ("rule.",)


def _setting_type(policy: dict) -> str:
    """Return the setting type of a policy without the "settings/" prefix."""
    return (policy.get("setting") or {}).get("type", "").removeprefix("settings/")


def _service_state(policy: dict) -> Optional[str]:
    """Return the serviceState a service status policy carries, if any."""
    return (((policy.get("setting") or {}).get("value")) or {}).get("serviceState")


def _sort_order(policy: dict) -> float:
    """Return the policy's sortOrder, or 0 when the API did not give one."""
    try:
        return float((policy.get("policyQuery") or {}).get("sortOrder") or 0)
    except (TypeError, ValueError):
        return 0.0


class ServicePolicies(BaseModel):
    """Base of the per-service policy models: carries the service status.

    `service_state` is the customer-level value of the service's
    `<service>.service_status` setting. `service_state_overridden` records
    that an organizational unit or group turns the service back on, in
    which case "off" at the customer level does not mean off for everyone.
    """

    service_state: Optional[str] = None
    service_state_overridden: bool = False

    @property
    def off_for_everyone(self) -> bool:
        """Whether the service is off at the customer level with no override.

        Settings that only act while the service is on have no effect then,
        so the checks on them pass with that reason. Settings that govern
        what already exists, such as Drive shares or Groups, keep being
        evaluated: Google keeps existing shares and groups reachable.
        """
        return self.service_state == "DISABLED" and not self.service_state_overridden


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

    def _list_policies(
        self, service, filter_str: str, context: str
    ) -> tuple[list[dict], bool]:
        """Read every Cloud Identity policy matching a filter, across pages.

        Returns the policies read and whether every page was read. A failing
        page is logged, the pages read before it are kept, and the caller
        decides what a partial read means for its checks.
        """
        policies: list[dict] = []
        try:
            request = service.policies().list(pageSize=100, filter=filter_str)
            while request is not None:
                response = request.execute()
                policies.extend(response.get("policies", []))
                request = service.policies().list_next(request, response)
        except Exception as error:
            self._handle_api_error(error, context, self.provider.identity.customer_id)
            return policies, False
        return policies, True

    def _effective_policies(self, policies: list[dict]) -> list[dict]:
        """Keep, per setting type, the customer-level policy Google applies.

        The API returns every policy that exists for a setting: Google's
        SYSTEM defaults next to the ADMIN policy saved in the Admin console.
        The value in force is the one with the greatest policyQuery.sortOrder,
        which is the Policy API's Max reducer, not the last one listed. Rule
        settings use the List reducer and are not reduced here: each policy is
        a distinct rule. Settings resolved with the Merge, MaxMap or MergeMap
        reducers combine several policies; this method keeps the greatest one
        for them too, which is exact only when that policy supplies the whole
        reduced value: every field, plus the array values Merge concatenates
        and the keyed entries MaxMap and MergeMap keep from policies with a
        lower sortOrder. Policies saved from the Admin console carry every
        field of the setting. Policies without a sort order keep the API order,
        so the last one wins.
        """
        kept: list[dict] = []
        position: dict[str, int] = {}
        for policy in policies:
            if not self._is_customer_level_policy(policy):
                continue
            setting_type = _setting_type(policy)
            if setting_type.startswith(LIST_SETTING_NAMESPACES):
                kept.append(policy)
                continue
            index = position.get(setting_type)
            if index is None:
                position[setting_type] = len(kept)
                kept.append(policy)
            elif _sort_order(policy) >= _sort_order(kept[index]):
                kept[index] = policy
        return kept

    def _service_status(
        self, policies: list[dict], setting_type: str
    ) -> tuple[Optional[str], bool]:
        """Return a service's customer-level state and whether anything overrides it.

        The state comes from the effective customer-level policy of the given
        `<service>.service_status` setting. A policy of that setting outside
        the customer scope counts as an override when it turns the service on,
        or when its scope could not be resolved: "off" then holds only for
        part of the tenant.
        """
        status_policies = [
            policy for policy in policies if _setting_type(policy) == setting_type
        ]
        overridden = any(
            self._overrides_service_status(policy) for policy in status_policies
        )
        effective = self._effective_policies(status_policies)
        state = _service_state(effective[0]) if effective else None
        return state, overridden

    def _overrides_service_status(self, policy: dict) -> bool:
        """Whether a status policy turns the service back on for part of the tenant.

        A sub-OU or group policy counts only when it does not say DISABLED: an
        OU that also turns the service off changes nothing, and Google lets an
        access group only turn a service on. A policy whose scope cannot be
        resolved counts as well, since it may be either.
        """
        scope = self._policy_scope(policy)
        if scope == CUSTOMER_SCOPE:
            return False
        return scope == UNKNOWN_SCOPE or _service_state(policy) != "DISABLED"

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
