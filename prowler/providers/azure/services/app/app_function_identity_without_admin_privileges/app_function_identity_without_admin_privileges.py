from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.config import (
    CONTRIBUTOR_ROLE_ID,
    OWNER_ROLE_ID,
    ROLE_BASED_ACCESS_CONTROL_ADMINISTRATOR_ROLE_ID,
    USER_ACCESS_ADMINISTRATOR_ROLE_ID,
)
from prowler.providers.azure.services.app.app_client import app_client
from prowler.providers.azure.services.iam.iam_client import iam_client


class app_function_identity_without_admin_privileges(Check):
    def execute(self):
        findings = []

        for (
            subscription_name,
            functions,
        ) in app_client.functions.items():
            for function in functions.values():
                if function.identity:
                    report = Check_Report_Azure(
                        metadata=self.metadata(), resource=function
                    )
                    report.subscription = subscription_name
                    report.status = "PASS"
                    report.status_extended = f"Function {function.name} has a managed identity enabled but without admin privileges."

                    admin_roles_assigned = []

                    for role_assignment in iam_client.role_assignments[
                        subscription_name
                    ].values():
                        if (
                            role_assignment.agent_id == function.identity.principal_id
                            and role_assignment.role_id
                            in [
                                CONTRIBUTOR_ROLE_ID,
                                OWNER_ROLE_ID,
                                ROLE_BASED_ACCESS_CONTROL_ADMINISTRATOR_ROLE_ID,
                                USER_ACCESS_ADMINISTRATOR_ROLE_ID,
                            ]
                        ):
                            admin_roles_assigned.append(
                                getattr(
                                    iam_client.roles[subscription_name].get(
                                        f"/subscriptions/{iam_client.subscriptions[subscription_name]}/providers/Microsoft.Authorization/roleDefinitions/{role_assignment.role_id}"
                                    ),
                                    "name",
                                    "",
                                )
                            )

                    if admin_roles_assigned:
                        report.status = "FAIL"
                        report.status_extended = f"Function {function.name} has a managed identity enabled and it is configure with admin privileges using {'roles: ' + ', '.join(admin_roles_assigned) if len(admin_roles_assigned) > 1 else 'role ' + admin_roles_assigned[0]}."

                    findings.append(report)

        return findings
