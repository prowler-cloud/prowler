from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.organizations.organizations_client import (
    organizations_client,
)


class organizations_account_part_of_organizations(Check):
    def execute(self):
        findings = []
        for org in organizations_client.organizations:
            report = Check_Report_AWS(self.metadata())
            if org.status == "ACTIVE":
                report.status = "PASS"
                report.status_extended = (
                    f"Account is part of AWS Organization: {org.id}"
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    "AWS Organizations is not in-use for this AWS Account"
                )
            report.resource_id = org.id
            report.resource_arn = org.arn
            findings.append(report)

        return findings
