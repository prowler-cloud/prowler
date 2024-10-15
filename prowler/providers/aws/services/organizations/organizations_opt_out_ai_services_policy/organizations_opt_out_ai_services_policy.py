from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.organizations.organizations_client import (
    organizations_client,
)


class organizations_opt_out_ai_services_policy(Check):
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
                    report.status_extended = f"AWS Organization {org.id} has not opted out of all AI services, granting consent for AWS to access its data."
                    for policy in org.policies.get("AISERVICES_OPT_OUT_POLICY", []):
                        if (
                            policy.content.get("services", {})
                            .get("default", {})
                            .get("opt_out_policy", {})
                            .get("@@assign")
                            == "optOut"
                        ):
                            report.status = "PASS"
                            report.status_extended = f"AWS Organization {org.id} has opted out of all AI services, not granting consent for AWS to access its data."
                            break

                findings.append(report)

        return findings
