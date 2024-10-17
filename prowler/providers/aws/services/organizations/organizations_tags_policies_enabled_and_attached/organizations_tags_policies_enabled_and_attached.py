from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.organizations.organizations_client import (
    organizations_client,
)


class organizations_tags_policies_enabled_and_attached(Check):
    def execute(self):
        findings = []

        for org in organizations_client.organizations:
            if org.policies is not None:  # Access Denied to list_policies
                report = Check_Report_AWS(self.metadata())
                report.resource_id = org.id
                report.resource_arn = org.arn
                report.region = organizations_client.region
                report.status = "FAIL"
                report.status_extended = (
                    "AWS Organizations is not in-use for this AWS Account."
                )

                if org.status == "ACTIVE":
                    report.status_extended = (
                        f"AWS Organizations {org.id} does not have tag policies."
                    )
                    for policy in org.policies.get("TAG_POLICY", []):
                        report.status_extended = f"AWS Organization {org.id} has tag policies enabled but not attached."
                        if policy.targets:
                            report.status = "PASS"
                            report.status_extended = f"AWS Organization {org.id} has tag policies enabled and attached to an AWS account."

                findings.append(report)

        return findings
