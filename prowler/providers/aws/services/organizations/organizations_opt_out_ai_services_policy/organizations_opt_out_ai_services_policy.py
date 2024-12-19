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
                    conditions_failed = []
                    all_conditions_passed = False
                    opt_out_policies = organizations_client.organization.policies.get(
                        "AISERVICES_OPT_OUT_POLICY", []
                    )

                    if not opt_out_policies:
                        report.status_extended = f"AWS Organization {organizations_client.organization.id} has no opt-out policy for AI services."
                    else:
                        for policy in opt_out_policies:
                            opt_out_policy = (
                                policy.content.get("services", {})
                                .get("default", {})
                                .get("opt_out_policy", {})
                            )

                            condition_1 = opt_out_policy.get("@@assign") == "optOut"
                            condition_2 = opt_out_policy.get(
                                "@@operators_allowed_for_child_policies"
                            ) == ["@@none"]

                            if condition_1 and condition_2:
                                all_conditions_passed = True
                                break

                            if not condition_1:
                                conditions_failed.append(
                                    "Organization has not opted out of all AI services."
                                )
                            if not condition_2:
                                conditions_failed.append(
                                    "Organization does not disallow child-accounts to overwrite the policy."
                                )

                        if all_conditions_passed:
                            report.status = "PASS"
                            report.status_extended = f"AWS Organization {organizations_client.organization.id} has opted out of all AI services and also disallows child-accounts to overwrite this policy."
                        else:
                            report.status_extended = (
                                f"AWS Organization {organizations_client.organization.id} failed the check due to the following reason(s): "
                                + " ".join(conditions_failed)
                            )

                findings.append(report)

        return findings
