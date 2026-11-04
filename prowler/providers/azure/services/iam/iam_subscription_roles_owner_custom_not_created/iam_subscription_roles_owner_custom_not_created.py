from fnmatch import fnmatch
from re import search

from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.iam.iam_client import iam_client

# Control-plane actions that make a custom role owner-equivalent. Azure
# computes effective permissions as Actions minus NotActions, so a wildcard
# action only counts as owner-equivalent when at least one of these
# capabilities survives the role's NotActions.
ROLE_ASSIGNMENT_CAPABILITIES = [
    "Microsoft.Authorization/*/Write",
    "Microsoft.Authorization/*/Delete",
    "Microsoft.Authorization/elevateAccess/Action",
]


def _as_list(value) -> list:
    """Normalize an Azure SDK action list, tolerating a bare string or None."""
    if not value:
        return []
    if isinstance(value, str):
        return [value]
    return list(value)


def _is_owner_equivalent(actions, not_actions) -> bool:
    """Return True when the wildcard action still grants role assignment.

    A role with a ``*`` action is owner-equivalent unless every role
    assignment capability above is removed by a matching NotAction pattern
    (Azure wildcard matching, case-insensitive).
    """
    if "*" not in _as_list(actions):
        return False
    not_actions = [pattern.lower() for pattern in _as_list(not_actions)]
    for capability in ROLE_ASSIGNMENT_CAPABILITIES:
        if not any(fnmatch(capability.lower(), pattern) for pattern in not_actions):
            return True
    return False


class iam_subscription_roles_owner_custom_not_created(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        for subscription, roles in iam_client.custom_roles.items():
            subscription_name = iam_client.subscriptions.get(subscription, subscription)
            for custom_role in roles.values():
                report = Check_Report_Azure(
                    metadata=self.metadata(), resource=custom_role
                )
                report.subscription = subscription
                report.status = "PASS"
                report.status_extended = f"Role {custom_role.name} from subscription {subscription_name} ({subscription}) is not a custom owner role."
                for scope in custom_role.assignable_scopes:
                    if search("^/.*", scope):
                        for permission_item in custom_role.permissions:
                            if _is_owner_equivalent(
                                getattr(permission_item, "actions", []),
                                getattr(permission_item, "not_actions", []),
                            ):
                                report.status = "FAIL"
                                report.status_extended = f"Role {custom_role.name} from subscription {subscription_name} ({subscription}) is a custom owner role."
                                break

                findings.append(report)
        return findings
