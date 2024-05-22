from re import search

from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.iam.iam_client import iam_client


class iam_custom_role_has_permissions_to_administer_resource_locks(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        for subscription, roles in iam_client.custom_roles.items():
            exits_role_with_permission_over_locks = False

            for custom_role in roles:
                if exits_role_with_permission_over_locks:
                    break
                report = Check_Report_Azure(self.metadata())
                report.subscription = subscription
                report.resource_id = custom_role.id
                report.resource_name = custom_role.name
                report.status = "FAIL"
                report.status_extended = f"Role {custom_role.name} from subscription {subscription} has no permission to administer resource locks."

                for permission_item in custom_role.permissions:
                    if exits_role_with_permission_over_locks:
                        break
                    for action in permission_item.actions:
                        if search("^Microsoft.Authorization/locks/.*", action):
                            report.status = "PASS"
                            report.status_extended = f"Role {custom_role.name} from subscription {subscription} has permission to administer resource locks."
                            exits_role_with_permission_over_locks = True
                            break
            findings.append(report)
        return findings
