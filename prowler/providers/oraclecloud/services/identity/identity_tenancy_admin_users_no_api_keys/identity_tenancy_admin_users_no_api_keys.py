"""Check Ensure API keys are not created for tenancy administrator users."""

from prowler.lib.check.models import Check, Check_Report_OCI
from prowler.providers.oraclecloud.services.identity.identity_client import (
    identity_client,
)


class identity_tenancy_admin_users_no_api_keys(Check):
    """Check Ensure API keys are not created for tenancy administrator users."""

    def execute(self) -> Check_Report_OCI:
        """Execute the identity_tenancy_admin_users_no_api_keys check."""
        findings = []

        # Check tenancy admin users for API keys
        for user in identity_client.users:
            # Check if user is in Administrators group
            is_admin = False
            for group_id in user.groups:
                for group in identity_client.groups:
                    if group.id == group_id and "Administrators" in group.name:
                        is_admin = True
                        break

            if is_admin:
                report = Check_Report_OCI(
                    metadata=self.metadata(),
                    resource=user,
                    region=user.region,
                    resource_name=user.name,
                    resource_id=user.id,
                    compartment_id=user.compartment_id,
                )

                if user.api_keys:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Tenancy administrator user {user.name} has API keys."
                    )
                else:
                    report.status = "PASS"
                    report.status_extended = (
                        f"Tenancy administrator user {user.name} has no API keys."
                    )

                findings.append(report)

        return findings
