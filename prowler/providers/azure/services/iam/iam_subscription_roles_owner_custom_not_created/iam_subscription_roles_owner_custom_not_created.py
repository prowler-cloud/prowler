from re import search

from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.iam.iam_client import iam_client


class iam_subscription_roles_owner_custom_not_created(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        if iam_client.resource_groups:
            for subscription in iam_client.subscriptions:
                report = Check_Report_Azure(metadata=self.metadata(), resource={})
                report.subscription = subscription
                report.resource_name = "Not Applicable"
                report.resource_id = "Not Applicable"
                report.status = "MANUAL"
                report.status_extended = f"Subscription '{subscription}': this check is subscription-scoped and cannot be evaluated when --azure-resource-group is active. Re-run without --azure-resource-group to get full results."
                findings.append(report)
            return findings
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
                            for action in permission_item.actions:
                                if action == "*":
                                    report.status = "FAIL"
                                    report.status_extended = f"Role {custom_role.name} from subscription {subscription_name} ({subscription}) is a custom owner role."
                                    break

                findings.append(report)
        return findings
