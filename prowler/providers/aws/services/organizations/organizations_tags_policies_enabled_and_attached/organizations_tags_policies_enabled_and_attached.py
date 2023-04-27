from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.organizations.organizations_client import (
    organizations_client,
)


class organizations_tags_policies_enabled_and_attached(Check):
    def execute(self):
        findings = []

        for org in organizations_client.organizations:
            report = Check_Report_AWS(self.metadata())
            report.resource_id = org.id
            report.resource_arn = org.arn
            report.region = organizations_client.region
            report.status = "FAIL"
            report.status_extended = (
                "AWS Organizations is not in-use for this AWS Account"
            )
            if org.status == "ACTIVE":
                if org.policies is None:
                    # Access Denied to list_policies
                    continue
                for policy in org.policies:
                    # We only check SCP policies here
                    if policy.type != "TAG_POLICY":
                        continue

                    report.status_extended = f"AWS Organization {org.id} has tag policies enabled but not attached"

                    if policy.targets:
                        report.status = "PASS"
                        report.status_extended = f"TAG Policies exist at the organization {org.id} level and are attached"

            findings.append(report)

        return findings
