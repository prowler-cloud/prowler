from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.organizations.organizations_client import (
    organizations_client,
)


class organizations_tags_policies_enabled_and_attached(Check):
    def execute(self):
        findings = []

        if organizations_client.organization:
            if (
                organizations_client.organization.policies is not None
            ):  # Access Denied to list_policies
                report = Check_Report_AWS(self.metadata())
                report.resource_id = organizations_client.organization.id
                report.resource_arn = organizations_client.organization.arn
                report.region = organizations_client.region
                report.status = "FAIL"
                report.status_extended = (
                    "AWS Organizations is not in-use for this AWS Account."
                )

                if organizations_client.organization.status == "ACTIVE":
                    report.status_extended = f"AWS Organizations {organizations_client.organization.id} does not have tag policies."
                    for policy in organizations_client.organization.policies.get(
                        "TAG_POLICY", []
                    ):
                        report.status_extended = f"AWS Organization {organizations_client.organization.id} has tag policies enabled but not attached."
                        if policy.targets:
                            report.status = "PASS"
                            report.status_extended = f"AWS Organization {organizations_client.organization.id} has tag policies enabled and attached to an AWS account."

                findings.append(report)

        return findings
