from re import compile

from prowler.config.config import get_config_var
from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.lib.policy_condition_parser.policy_condition_parser import (
    is_account_only_allowed_in_condition,
)
from prowler.providers.aws.services.vpc.vpc_client import vpc_client


class vpc_endpoint_connections_trust_boundaries(Check):
    def execute(self):
        findings = []
        # Get trusted account_ids from prowler.config.yaml
        trusted_account_ids = get_config_var("trusted_account_ids")
        for endpoint in vpc_client.vpc_endpoints:
            # Check VPC endpoint policy
            if endpoint.policy_document:
                full_access = False
                for statement in endpoint.policy_document["Statement"]:
                    if "*" == statement["Principal"]:
                        report = Check_Report_AWS(self.metadata())
                        report.region = endpoint.region
                        report.resource_id = endpoint.id
                        report.resource_arn = endpoint.arn
                        report.resource_tags = endpoint.tags
                        if (
                            "Condition" in statement
                            and is_account_only_allowed_in_condition(
                                statement["Condition"], trusted_account_ids
                            )
                        ):
                            report.status = "PASS"
                            report.status_extended = f"VPC Endpoint {endpoint.id} in VPC {endpoint.vpc_id} can only be accessed from the same account."
                        else:
                            full_access = True
                            report.status = "FAIL"
                            report.status_extended = f"VPC Endpoint {endpoint.id} in VPC {endpoint.vpc_id} has full access."

                        findings.append(report)

                        if full_access:
                            break

                    else:
                        if type(statement["Principal"]["AWS"]) == str:
                            principals = [statement["Principal"]["AWS"]]
                        else:
                            principals = statement["Principal"]["AWS"]
                        for principal_arn in principals:
                            if principal_arn == "*":
                                report = Check_Report_AWS(self.metadata())
                                report.region = endpoint.region
                                report.resource_id = endpoint.id
                                report.resource_arn = endpoint.arn
                                report.resource_tags = endpoint.tags

                                report.status = "FAIL"
                                report.status_extended = f"VPC Endpoint {endpoint.id} in VPC {endpoint.vpc_id} has full access."
                                if (
                                    "Condition" in statement
                                    and is_account_only_allowed_in_condition(
                                        statement["Condition"], trusted_account_ids
                                    )
                                ):
                                    report.status = "PASS"
                                    report.status_extended = f"VPC Endpoint {endpoint.id} in VPC {endpoint.vpc_id} can only be accessed from the trusted account."

                                else:
                                    full_access = True
                                    report.status = "FAIL"
                                    report.status_extended = f"VPC Endpoint {endpoint.id} in VPC {endpoint.vpc_id} has full access."

                                findings.append(report)
                                if full_access:
                                    break
                            else:
                                # Account ID can be an ARN or just a 12-digit string
                                pattern = compile(r"^[0-9]{12}$")
                                match = pattern.match(principal_arn)
                                if not match:
                                    account_id = principal_arn.split(":")[4]
                                else:
                                    account_id = match.string
                                if (
                                    account_id in trusted_account_ids
                                    or account_id in vpc_client.audited_account
                                ):
                                    report = Check_Report_AWS(self.metadata())
                                    report.region = endpoint.region
                                    report.status = "PASS"
                                    report.status_extended = f"Found trusted account {account_id} in VPC Endpoint {endpoint.id} in VPC {endpoint.vpc_id}."
                                    report.resource_id = endpoint.id
                                    report.resource_arn = endpoint.arn
                                    report.resource_tags = endpoint.tags
                                else:
                                    report = Check_Report_AWS(self.metadata())
                                    report.region = endpoint.region
                                    report.resource_id = endpoint.id
                                    report.resource_arn = endpoint.arn
                                    report.resource_tags = endpoint.tags
                                    if (
                                        "Condition" in statement
                                        and is_account_only_allowed_in_condition(
                                            statement["Condition"], trusted_account_ids
                                        )
                                    ):
                                        report.status = "PASS"
                                        report.status_extended = f"VPC Endpoint {endpoint.id} in VPC {endpoint.vpc_id} can only be accessed from the trusted account."
                                    else:
                                        report.status = "FAIL"
                                        report.status_extended = f"Found untrusted account {account_id} in VPC Endpoint {endpoint.id} in VPC {endpoint.vpc_id}."

                                findings.append(report)
        return findings
