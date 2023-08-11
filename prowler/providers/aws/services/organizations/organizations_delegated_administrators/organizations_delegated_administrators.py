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

        for org in organizations_client.organizations:
            if org.status == "ACTIVE":
                report = Check_Report_AWS(self.metadata())
                report.resource_id = org.id
                report.resource_arn = org.arn
                report.region = organizations_client.region
                if org.delegated_administrators is None:
                    # Access Denied to list_policies
                    continue
                if org.delegated_administrators:
                    for delegated_administrator in org.delegated_administrators:
                        if (
                            delegated_administrator.id
                            not in organizations_trusted_delegated_administrators
                        ):
                            report.status = "FAIL"
                            report.status_extended = f"Untrusted Delegated Administrators: {delegated_administrator.id}."
                        else:
                            report.status = "PASS"
                            report.status_extended = f"Trusted Delegated Administrator: {delegated_administrator.id}."
                else:
                    report.status = "PASS"
                    report.status_extended = f"No Delegated Administrators: {org.id}."

                findings.append(report)

        return findings
