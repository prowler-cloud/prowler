from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.organizations.organizations_client import (
    organizations_client,
)


class organizations_delegated_administrators(Check):
    def execute(self):
        findings = []

        organizations_trusted_delegated_administrators = (
            organizations_client.audit_config.get(
                "organizations_trusted_delegated_administrators", []
            )
        )

        if (
            organizations_client.organization
            and organizations_client.organization.status == "ACTIVE"
        ):
            report = Check_Report_AWS(self.metadata())
            report.resource_id = organizations_client.organization.id
            report.resource_arn = organizations_client.organization.arn
            report.region = organizations_client.region
            if (
                organizations_client.organization.delegated_administrators is not None
            ):  # Check if Access Denied to list_delegated_administrators
                if organizations_client.organization.delegated_administrators:
                    for (
                        delegated_administrator
                    ) in organizations_client.organization.delegated_administrators:
                        if (
                            delegated_administrator.id
                            not in organizations_trusted_delegated_administrators
                        ):
                            report.status = "FAIL"
                            report.status_extended = f"AWS Organization {organizations_client.organization.id} has an untrusted Delegated Administrator: {delegated_administrator.id}."
                        else:
                            report.status = "PASS"
                            report.status_extended = f"AWS Organization {organizations_client.organization.id} has a trusted Delegated Administrator: {delegated_administrator.id}."
                else:
                    report.status = "PASS"
                    report.status_extended = f"AWS Organization {organizations_client.organization.id} has no Delegated Administrators."

                findings.append(report)

        return findings
