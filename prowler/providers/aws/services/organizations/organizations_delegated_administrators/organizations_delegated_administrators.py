from prowler.config.config import get_config_var
from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.organizations.organizations_client import (
    organizations_client,
)


class organizations_delegated_administrators(Check):
    def execute(self):
        findings = []
        organizations_trusted_delegated_administrators = get_config_var(
            "organizations_trusted_delegated_administrators"
        )

        for org in organizations_client.organizations:
            report = Check_Report_AWS(self.metadata())
            report.resource_id = org.id
            report.resource_arn = org.arn
            if org.status == "ACTIVE":
                if org.delegated_administrators:
                    if (
                        org.delegated_administrators
                        == organizations_trusted_delegated_administrators
                    ):
                        report.status = "PASS"
                        report.status_extended = (
                            f"Delegated Administrators are trusted: {org.id}"
                        )
                    else:
                        report.status = "FAIL"
                        report.status_extended = (
                            f"Untrusted Deledated Administrators: {org.id}"
                        )
                else:
                    report.status = "PASS"
                    report.status_extended = f"No Delegated Administrators: {org.id}"
            else:
                report.status = "PASS"
                report.status_extended = (
                    "AWS Organizations is not in-use for this AWS Account"
                )

            findings.append(report)

        return findings
