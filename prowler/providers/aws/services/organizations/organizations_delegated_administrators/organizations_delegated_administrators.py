from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.organizations.organizations_client import (
    organizations_client,
)


class organizations_delegated_administrators(Check):
    """Ensure every AWS Organizations delegated administrator is in the trusted list."""

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check logic.

        Returns:
            One report for the organization, or none if the account is not in an
            active organization.
        """
        findings = []

        # `or []` also covers the key being set to null in the config file
        organizations_trusted_delegated_administrators = (
            organizations_client.audit_config.get(
                "organizations_trusted_delegated_administrators", []
            )
            or []
        )

        if (
            organizations_client.organization
            and organizations_client.organization.status == "ACTIVE"
        ):
            report = Check_Report_AWS(
                metadata=self.metadata(),
                resource=organizations_client.organization,
            )
            report.region = organizations_client.region
            delegated_administrators = (
                organizations_client.organization.delegated_administrators
            )
            if delegated_administrators is None:
                # Unreadable (only the management or a delegated administrator account
                # can list them): no finding rather than a verdict on unknown data.
                return findings
            if delegated_administrators:
                # Sorted so the verdict and text do not depend on the API's list order
                untrusted = sorted(
                    administrator.id
                    for administrator in delegated_administrators
                    if administrator.id
                    not in organizations_trusted_delegated_administrators
                )
                trusted = sorted(
                    administrator.id
                    for administrator in delegated_administrators
                    if administrator.id
                    in organizations_trusted_delegated_administrators
                )
                if untrusted:
                    report.status = "FAIL"
                    subject = (
                        "an untrusted Delegated Administrator"
                        if len(untrusted) == 1
                        else "untrusted Delegated Administrators"
                    )
                    report.status_extended = f"AWS Organization {organizations_client.organization.id} has {subject}: {', '.join(untrusted)}."
                else:
                    report.status = "PASS"
                    subject = (
                        "a trusted Delegated Administrator"
                        if len(trusted) == 1
                        else "trusted Delegated Administrators"
                    )
                    report.status_extended = f"AWS Organization {organizations_client.organization.id} has {subject}: {', '.join(trusted)}."
            else:
                report.status = "PASS"
                report.status_extended = f"AWS Organization {organizations_client.organization.id} has no Delegated Administrators."

            findings.append(report)

        return findings
