from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.organizations.organizations_client import (
    organizations_client,
)

# Security services whose organization-wide administration can be delegated to a member
# account ("Supports delegated administrator: Yes" in
# https://docs.aws.amazon.com/organizations/latest/userguide/orgs_integrate_services_list.html).
# CloudTrail is left out: the management account keeps owning organization trails even
# with a delegated administrator, so delegating it does not move administration away.
SECURITY_SERVICE_PRINCIPALS = {
    "access-analyzer.amazonaws.com",
    "auditmanager.amazonaws.com",
    "config-multiaccountsetup.amazonaws.com",
    "config.amazonaws.com",
    "detective.amazonaws.com",
    "fms.amazonaws.com",
    "guardduty.amazonaws.com",
    "inspector2.amazonaws.com",
    "macie.amazonaws.com",
    "security-ir.amazonaws.com",
    "securityhub.amazonaws.com",
    "securitylake.amazonaws.com",
}


class organizations_security_services_delegated_admin_not_management_account(Check):
    """Ensure security services with trusted access have a delegated administrator.

    Organizations rejects the management account as a delegated administrator, so a
    security service with trusted access enabled and no delegated administrator is
    administered from the management account.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check logic.

        Returns:
            One report for the organization, or none if the account is not in an
            active organization, the delegations cannot be read, or no security
            service has trusted access enabled.
        """
        findings = []

        organization = organizations_client.organization
        if not organization or organization.status != "ACTIVE":
            return findings

        enabled_service_principals = organization.enabled_service_principals
        delegated_service_principals = organization.delegated_service_principals

        # Unreadable (only the management or a delegated administrator account can
        # read these): no finding rather than a verdict on unknown data.
        if (
            organization.delegated_administrators is None
            or enabled_service_principals is None
            or delegated_service_principals is None
            or None in delegated_service_principals.values()
        ):
            return findings

        integrated_security_services = sorted(
            SECURITY_SERVICE_PRINCIPALS.intersection(enabled_service_principals)
        )
        if not integrated_security_services:
            return findings

        report = Check_Report_AWS(metadata=self.metadata(), resource=organization)
        report.region = organizations_client.region

        delegated = {
            principal
            for principals in delegated_service_principals.values()
            for principal in principals
        }
        not_delegated = [
            principal
            for principal in integrated_security_services
            if principal not in delegated
        ]

        if not_delegated:
            report.status = "FAIL"
            report.status_extended = f"AWS Organization {organization.id} administers {', '.join(not_delegated)} from the management account {organization.master_id} instead of a delegated administrator account."
        else:
            report.status = "PASS"
            report.status_extended = f"AWS Organization {organization.id} administers {', '.join(integrated_security_services)} from delegated administrator accounts other than the management account {organization.master_id}."

        findings.append(report)

        return findings
