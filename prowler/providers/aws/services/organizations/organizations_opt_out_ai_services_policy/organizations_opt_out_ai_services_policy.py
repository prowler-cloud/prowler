from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.organizations.organizations_client import (
    organizations_client,
)


class organizations_opt_out_ai_services_policy(Check):
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
                    report.status_extended = f"AWS Organization {organizations_client.organization.id} has not opted out of all AI services, granting consent for AWS to access its data, or does not disallow child-accounts to overwrite this policy."
                    for policy in organizations_client.organization.policies.get(
                        "AISERVICES_OPT_OUT_POLICY", []
                    ):
                        opt_out_policy = (
                            policy.content.get("services", {})
                            .get("default", {})
                            .get("opt_out_policy", {})
                        )
                        if opt_out_policy.get(
                            "@@assign"
                        ) == "optOut" and opt_out_policy.get(
                            "@@operators_allowed_for_child_policies"
                        ) == [
                            "@@none"
                        ]:
                            report.status = "PASS"
                            report.status_extended = f"AWS Organization {organizations_client.organization.id} has opted out of all AI services, not granting consent for AWS to access its data, and also disallows child-accounts to overwrite this policy."
                            break

                findings.append(report)

        return findings
