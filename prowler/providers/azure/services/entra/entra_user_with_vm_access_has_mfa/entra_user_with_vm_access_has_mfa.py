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


class entra_user_with_vm_access_has_mfa(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for users in entra_client.users.values():
            for user_domain_name, user in users.items():
                for (
                    subscription_name,
                    role_assigns,
                ) in iam_client.role_assignments.items():
                    for assignment in role_assigns.values():
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
                            report.status_extended = f"User {user.name} without MFA can access VMs in subscription {subscription_name}"
                            report.subscription = subscription_name
                            report.resource_name = user_domain_name
                            report.resource_id = user.id

                            if len(user.authentication_methods) > 1:
                                report.status = "PASS"
                                report.status_extended = f"User {user.name} can access VMs in subscription {subscription_name} but it has MFA."

                            findings.append(report)

        return findings
