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
                    report.status_extended = (
                        f"No SCP policies exist at the organization {org.id} level"
                    )
                else:
                    # We use this flag if we find a statement that is restricting regions but not all the configured ones:
                    is_region_restricted_statement = False

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
                                    # All defined regions are restricted, we exit here, no need to continue.
                                    report.status = "PASS"
                                    report.status_extended = f"SCP policy {policy.id} restricting all configured regions found"
                                    findings.append(report)
                                    return findings
                                else:
                                    # Regions are restricted, but not the ones defined, we keep this finding, but we continue analyzing:
                                    is_region_restricted_statement = True
                                    report.status = "FAIL"
                                    report.status_extended = f"SCP policies exist {policy.id} restricting some AWS Regions, but not all the configured ones, please check config..."

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
                                    # All defined regions are restricted, we exit here, no need to continue.
                                    report.status = "PASS"
                                    report.status_extended = f"SCP policy {policy.id} restricting all configured regions found"
                                    findings.append(report)
                                    return findings
                                else:
                                    # Regions are restricted, but not the ones defined, we keep this finding, but we continue analyzing:
                                    is_region_restricted_statement = True
                                    report.status = "FAIL"
                                    report.status_extended = f"SCP policies exist {policy.id} restricting some AWS Regions, but not all the configured ones, please check config..."

                    if not is_region_restricted_statement:
                        report.status = "FAIL"
                        report.status_extended = f"SCP policies exist at the organization {org.id} level but don't restrict AWS Regions"

            else:
                report.status = "FAIL"
                report.status_extended = (
                    "AWS Organizations is not in-use for this AWS Account"
                )

            findings.append(report)

        return findings
