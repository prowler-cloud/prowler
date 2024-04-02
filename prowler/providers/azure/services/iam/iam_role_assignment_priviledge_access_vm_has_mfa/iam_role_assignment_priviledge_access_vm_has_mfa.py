from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.config import (
    CONTRIBUTOR_ROLE_ID,
    OWNER_ROLE_ID,
    VIRTUAL_MACHINE_ADMINISTRATOR_LOGIN_ROLE_ID,
    VIRTUAL_MACHINE_CONTRIBUTOR_ROLE_ID,
    VIRTUAL_MACHINE_LOCAL_USER_LOGIN_ROLE_ID,
    VIRTUAL_MACHINE_USER_LOGIN_ROLE_ID,
    WINDOWS_ADMIN_CENTER_ADMINISTRATOR_LOGIN_ROLE_ID,
)
from prowler.providers.azure.services.entra.entra_client import entra_client
from prowler.providers.azure.services.iam.iam_client import iam_client


class iam_role_assignment_priviledge_access_vm_has_mfa(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for users in entra_client.users.values():
            for user_domain_name, user in users.items():
                for (
                    subscription_name,
                    role_assigns,
                ) in iam_client.role_assignments.items():
                    for assignment_id, assignment in role_assigns.items():
                        if (
                            assignment.agent_type == "User"
                            and assignment.role_id
                            in [
                                CONTRIBUTOR_ROLE_ID,
                                OWNER_ROLE_ID,
                                VIRTUAL_MACHINE_CONTRIBUTOR_ROLE_ID,
                                VIRTUAL_MACHINE_ADMINISTRATOR_LOGIN_ROLE_ID,
                                VIRTUAL_MACHINE_USER_LOGIN_ROLE_ID,
                                VIRTUAL_MACHINE_LOCAL_USER_LOGIN_ROLE_ID,
                                WINDOWS_ADMIN_CENTER_ADMINISTRATOR_LOGIN_ROLE_ID,
                            ]
                            and assignment.agent_id == user.id
                        ):
                            report = Check_Report_Azure(self.metadata())
                            report.status = "FAIL"
                            report.status_extended = f"User '{user.name}' has no MFA and can access VMs with privileges in subscription {subscription_name}"
                            report.subscription = subscription_name
                            report.resource_name = user_domain_name
                            report.resource_id = assignment_id

                            if len(user.authentication_methods) > 1:
                                report.status = "PASS"
                                report.status_extended = f"User '{user.name}' has MFA and can access VMs with privileges in subscription {subscription_name}"

                            findings.append(report)

        return findings
