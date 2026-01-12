"""Check Ensure IAM administrators cannot update tenancy Administrators group."""

from prowler.lib.check.models import Check, Check_Report_OCI
from prowler.providers.oraclecloud.services.identity.identity_client import (
    identity_client,
)


class identity_iam_admins_cannot_update_tenancy_admins(Check):
    """Check Ensure IAM administrators cannot update tenancy Administrators group."""

    def execute(self) -> Check_Report_OCI:
        """Execute the identity_iam_admins_cannot_update_tenancy_admins check."""
        findings = []

        # Policies that grant manage/use on groups or users in tenancy must have
        # a where clause with "target.group.name != 'Administrators'"

        for policy in identity_client.policies:
            # Skip default tenant admin policies
            if policy.name.lower() in ["tenant admin policy", "psm-root-policy"]:
                continue

            policy_has_issue = False
            problematic_statements = []

            for statement in policy.statements:
                statement_upper = statement.upper()

                # Check if statement grants manage/use on groups or users in tenancy
                if (
                    "ALLOW GROUP" in statement_upper
                    and "TENANCY" in statement_upper
                    and ("TO MANAGE" in statement_upper or "TO USE" in statement_upper)
                    and (
                        "ALL-RESOURCES" in statement_upper
                        or (
                            " GROUPS " in statement_upper
                            and " USERS " in statement_upper
                        )
                    )
                ):
                    # Check if there's a where clause protecting Administrators group
                    split_statement = statement.split("where")

                    if len(split_statement) == 2:
                        # Has a where clause - check if it protects Administrators group
                        clean_where_clause = (
                            split_statement[1]
                            .upper()
                            .replace(" ", "")
                            .replace("'", "")
                            .replace('"', "")
                        )

                        # Check if the where clause contains target.group.name != Administrators
                        if (
                            "TARGET.GROUP.NAME!=ADMINISTRATORS"
                            not in clean_where_clause
                        ):
                            policy_has_issue = True
                            problematic_statements.append(statement)
                    else:
                        # No where clause - this is a violation
                        policy_has_issue = True
                        problematic_statements.append(statement)

            if policy_has_issue:
                report = Check_Report_OCI(
                    metadata=self.metadata(),
                    resource=policy,
                    region=policy.region,
                    resource_name=policy.name,
                    resource_id=policy.id,
                    compartment_id=policy.compartment_id,
                )
                report.status = "FAIL"
                report.status_extended = (
                    f"Policy '{policy.name}' grants manage/use permissions on groups or users in tenancy "
                    f"without restricting access to the Administrators group. "
                    f"Problematic statements: {len(problematic_statements)}"
                )
                findings.append(report)

        # If no violations found, create a PASS finding
        if not findings:
            region = (
                identity_client.audited_regions[0].key
                if identity_client.audited_regions
                else "global"
            )
            report = Check_Report_OCI(
                metadata=self.metadata(),
                resource={},
                region=region,
                resource_name="IAM Policies",
                resource_id=identity_client.audited_tenancy,
                compartment_id=identity_client.audited_tenancy,
            )
            report.status = "PASS"
            report.status_extended = (
                "All IAM policies that grant manage/use permissions on groups or users "
                "properly restrict access to the Administrators group."
            )
            findings.append(report)

        return findings
