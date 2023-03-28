from prowler.config.config import get_config_var
from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.organizations.organizations_client import (
    organizations_client,
)


class organizations_scp_check_deny_regions(Check):
    def execute(self):
        findings = []
        organizations_enabled_regions = get_config_var("organizations_enabled_regions")

        for org in organizations_client.organizations:
            report = Check_Report_AWS(self.metadata())
            report.resource_id = org.id
            report.resource_arn = org.arn
            if org.status == "ACTIVE":
                if not org.policies:
                    report.status = "FAIL"
                    report.status_extended = f"No SCP policies found for org: {org.id}"
                else:
                    # We need to check all policies and statements, but to find at least one denying regions.
                    scp_check_deny_all_regions = False
                    scp_check_deny_some_regions = False

                    for policy in org.policies:
                        # Statements are not always list
                        statements = policy.content.get("Statement")
                        if type(policy.content["Statement"]) is not list:
                            statements = [policy.content.get("Statement")]

                        for statement in statements:
                            # Deny if Condition = {"StringNotEquals": {"aws:RequestedRegion": [region1, region2]}}
                            if (
                                statement.get("Effect") == "Deny"
                                and "Condition" in statement
                                and "StringNotEquals" in statement["Condition"]
                                and "aws:RequestedRegion"
                                in statement["Condition"]["StringNotEquals"]
                            ):
                                if (
                                    organizations_enabled_regions
                                    == statement["Condition"]["StringNotEquals"][
                                        "aws:RequestedRegion"
                                    ]
                                ):
                                    # We found the statement, no need to continue
                                    scp_check_deny_all_regions = True
                                    break
                                else:
                                    # We found a statement restricting some regions, we continue to check if there is another one more restrictive
                                    scp_check_deny_some_regions = True

                            # Allow if Condition = {"StringEquals": {"aws:RequestedRegion": [region1, region2]}}
                            if (
                                policy.content.get("Statement") == "Allow"
                                and "Condition" in statement
                                and "StringEquals" in statement["Condition"]
                                and "aws:RequestedRegion"
                                in statement["Condition"]["StringEquals"]
                            ):
                                if (
                                    organizations_enabled_regions
                                    == statement["Condition"]["StringEquals"][
                                        "aws:RequestedRegion"
                                    ]
                                ):
                                    # We found the statement, no need to continue
                                    scp_check_deny_all_regions = True
                                    break
                                else:
                                    # We found a statement restricting some regions, we continue to check if there is another one more restrictive
                                    scp_check_deny_some_regions = True

                        if scp_check_deny_all_regions:
                            report.status = "PASS"
                            report.status_extended = (
                                f"SCP policy restricting regions found: {policy.id}"
                            )
                            findings.append(report)
                            return findings

                    if scp_check_deny_some_regions:
                        report.status = "FAIL"
                        report.status_extended = f"SCP policy restricting regions found: {policy.id}, but not the configured ones, check config..."
                        findings.append(report)
                        return findings

                    report.status = "FAIL"
                    report.status_extended = (
                        f"No SCP restricting by regions found for org: {org.id}"
                    )

            else:
                report.status = "FAIL"
                report.status_extended = (
                    "AWS Organizations is not in-use for this AWS Account"
                )

            findings.append(report)

        return findings
