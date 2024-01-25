from re import search

from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.iam.iam_client import iam_client


class iam_custom_role_has_permissions_to_administer_resource_locks(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        for subscription, roles in iam_client.custom_roles.items():
            for role in roles:
                report = Check_Report_Azure(self.metadata())
                report.subscription = subscription
                report.resource_id = role.id
                report.resource_name = role.name
                has_lock_permission = False
                for permission_item in role.permissions:
                    if has_lock_permission:
                        break
                    for action in permission_item.actions:
                        if has_lock_permission:
                            break
                        if search("^Microsoft.Authorization/locks/.*", action):
                            report.status = "PASS"
                            report.status_extended = f"Role {role.name} from subscription {subscription} has permission to administer resource locks."
                            has_lock_permission = True
                            break
                        else:
                            report.status = "FAIL"
                            report.status_extended = f"Role {role.name} from subscription {subscription} has no permission to administer resource locks."
                            break
                findings.append(report)
        return findings
