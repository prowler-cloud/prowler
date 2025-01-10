from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.organizations.organizations_client import (
    organizations_client,
)


class organizations_account_part_of_organizations(Check):
    def execute(self):
        findings = []
        if organizations_client.organization:
            report = Check_Report_AWS(self.metadata())
            if organizations_client.organization.status == "ACTIVE":
                report.status = "PASS"
                report.status_extended = f"AWS Organization {organizations_client.organization.id} contains this AWS account."
            else:
                report.status = "FAIL"
                report.status_extended = (
                    "AWS Organizations is not in-use for this AWS Account."
                )
            report.region = organizations_client.region
            report.resource_id = organizations_client.organization.id
            report.resource_arn = organizations_client.organization.arn
            findings.append(report)

        return findings
