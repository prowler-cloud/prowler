from re import search

from lib.check.models import Check, Check_Report
from providers.azure.services.aad.aad_client import aad_client


class aad_subscription_roles_owner_custom_not_created(Check):
    def execute(self) -> Check_Report:
        findings = []
        for role in aad_client.roles:
            report = Check_Report(self.metadata)
            report.region = aad_client.region
            report.status = "PASS"
            report.status_extended = f"Role {role.name} from subscription {role.role_subscription} is not a custom owner role"
            for scope in role.assignable_scopes:
                if search("^/.*", scope):
                    for permission_item in role.permissions:
                        for action in permission_item.actions:
                            if action == "*":
                                report.status = "FAIL"
                                report.status_extended = f"Role {role.name} from subscription {role.role_subscription} is a custom owner role"
                                break

            findings.append(report)
        return findings
