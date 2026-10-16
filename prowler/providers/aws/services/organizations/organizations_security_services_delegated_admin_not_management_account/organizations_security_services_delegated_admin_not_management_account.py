from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.organizations.organizations_client import (
    organizations_client,
)

# Service principals of the AWS security services whose organization-wide
# administration can be handed to a member account, taken from the rows of
# https://docs.aws.amazon.com/organizations/latest/userguide/orgs_integrate_services_list.html
# whose "Supports delegated administrator" column is Yes.
SECURITY_SERVICE_PRINCIPALS = {
    "access-analyzer.amazonaws.com",
    "auditmanager.amazonaws.com",
    "cloudtrail.amazonaws.com",
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
    """Ensure the security services integrated with the organization are administered
    from a delegated administrator account rather than the management account.

    Every security service that has trusted access enabled is administered
    organization-wide, and registering a delegated administrator is the only way to
    move that administration out of the management account. A service with trusted
    access enabled and no delegated administrator is therefore administered from the
    management account.

    The management account is also compared against the registered delegated
    administrators. Organizations rejects that registration today with
    CANNOT_REGISTER_MASTER_AS_DELEGATED_ADMINISTRATOR, so this clause guards against
    that constraint changing rather than against a configuration seen in the wild.

    The management account ID is a required field of the organization, so an audited
    account whose DescribeOrganization response stops carrying it has no organization
    at all and reaches no verdict here rather than being compared against an empty
    account ID.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check logic.

        Returns:
            A single report for the organization, or no report when the audited
            account is not part of an organization or when the organization
            integrates no security service at all.
        """
        findings = []

        organization = organizations_client.organization
        if not organization or organization.status != "ACTIVE":
            return findings

        report = Check_Report_AWS(metadata=self.metadata(), resource=organization)
        report.region = organizations_client.region

        delegated_administrators = organization.delegated_administrators
        enabled_service_principals = organization.enabled_service_principals
        delegated_service_principals = organization.delegated_service_principals

        # The Organizations reads this check needs are only available to the
        # management account and to delegated administrators: not being able to make
        # them is a lack of visibility, not a misconfiguration.
        if (
            delegated_administrators is None
            or enabled_service_principals is None
            or delegated_service_principals is None
            or any(
                principals is None
                for principals in delegated_service_principals.values()
            )
        ):
            report.status = "MANUAL"
            # Three different reads leave this same sentinel and only one of them
            # records an error code, so the cause is genuinely unknown here: the text
            # names what the caller can check without asserting which read failed, and
            # keeps the retry in it because a throttle arrives as this branch too.
            report.status_extended = (
                f"AWS Organization {organization.id} delegated administration of the "
                f"security services could not be determined; run this check from the "
                f"organization management account or a registered delegated "
                f"administrator allowed organizations:ListDelegatedAdministrators, "
                f"organizations:ListAWSServiceAccessForOrganization and "
                f"organizations:ListDelegatedServicesForAccount, and retry if the "
                f"failure was transient."
            )
            findings.append(report)
            return findings

        # Trusted access off for every security service is an empty scope, not an
        # undetermined one, so it reports nothing rather than sharing the MANUAL above --
        # the same shape as an account outside an organization.
        integrated_security_services = sorted(
            SECURITY_SERVICE_PRINCIPALS.intersection(enabled_service_principals)
        )
        if not integrated_security_services:
            return findings

        administered_from_management_account = []
        for service_principal in integrated_security_services:
            administrators = [
                account_id
                for account_id, principals in delegated_service_principals.items()
                if service_principal in principals
            ]
            if not administrators or organization.master_id in administrators:
                administered_from_management_account.append(service_principal)

        if administered_from_management_account:
            report.status = "FAIL"
            report.status_extended = (
                f"AWS Organization {organization.id} administers "
                f"{', '.join(administered_from_management_account)} from the "
                f"management account {organization.master_id} instead of a delegated "
                f"administrator account."
            )
        else:
            report.status = "PASS"
            report.status_extended = (
                f"AWS Organization {organization.id} administers "
                f"{', '.join(integrated_security_services)} from delegated "
                f"administrator accounts other than the management account "
                f"{organization.master_id}."
            )

        findings.append(report)

        return findings
