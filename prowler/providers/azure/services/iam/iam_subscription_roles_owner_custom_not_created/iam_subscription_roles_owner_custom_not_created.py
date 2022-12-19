from re import search

from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.iam.iam_client import iam_client


class iam_subscription_roles_owner_custom_not_created(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        for subscription, roles in iam_client.roles.items():
            for role in roles:
                report = Check_Report_Azure(self.metadata())
                report.subscription = subscription
                report.resource_id = role.id
                report.resource_name = role.name
                report.status = "PASS"
                report.status_extended = f"Role {role.name} from subscription {subscription} is not a custom owner role"
                for scope in role.assignable_scopes:
                    if search("^/.*", scope):
                        for permission_item in role.permissions:
                            for action in permission_item.actions:
                                if action == "*":
                                    report.status = "FAIL"
                                    report.status_extended = f"Role {role.name} from subscription {subscription} is a custom owner role"
                                    break

                findings.append(report)
        return findings
