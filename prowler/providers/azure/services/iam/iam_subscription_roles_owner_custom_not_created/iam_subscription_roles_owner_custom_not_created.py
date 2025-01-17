from re import search

from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.iam.iam_client import iam_client


class iam_subscription_roles_owner_custom_not_created(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        for subscription, roles in iam_client.custom_roles.items():
            for custom_role in roles:
                report = Check_Report_Azure(
                    metadata=self.metadata(), resource=custom_role
                )
                report.subscription = subscription
                report.status = "PASS"
                report.status_extended = f"Role {custom_role.name} from subscription {subscription} is not a custom owner role."
                for scope in custom_role.assignable_scopes:
                    if search("^/.*", scope):
                        for permission_item in custom_role.permissions:
                            for action in permission_item.actions:
                                if action == "*":
                                    report.status = "FAIL"
                                    report.status_extended = f"Role {custom_role.name} from subscription {subscription} is a custom owner role."
                                    break

                findings.append(report)
        return findings
