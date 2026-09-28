from re import fullmatch

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.lib.policy import (
    is_condition_block_restrictive_for_trusted_accounts,
)
from prowler.providers.aws.services.vpc.vpc_client import vpc_client


class vpc_endpoint_connections_trust_boundaries(Check):
    def execute(self):
        findings = []
        trusted_account_ids = set(
            vpc_client.audit_config.get("trusted_account_ids", [])
        )
        trusted_account_ids.add(vpc_client.audited_account)

        for endpoint in vpc_client.vpc_endpoints:
            if (
                not endpoint.policy_document
                or "com.amazonaws.vpce." in endpoint.service_name
            ):
                continue

            for statement in endpoint.policy_document["Statement"]:
                principal = statement["Principal"]
                if principal == "*":
                    principals = ["*"]
                elif isinstance(principal, dict) and "AWS" in principal:
                    aws_principals = principal["AWS"]
                    principals = (
                        [aws_principals]
                        if isinstance(aws_principals, str)
                        else aws_principals
                    )
                else:
                    continue

                caller_condition_restrictive = (
                    "Condition" in statement
                    and is_condition_block_restrictive_for_trusted_accounts(
                        statement["Condition"], trusted_account_ids
                    )
                )
                access_from_trusted_accounts = True
                for principal_arn in principals:
                    principal_trusted = False
                    if principal_arn != "*":
                        account_id = (
                            principal_arn
                            if fullmatch(r"[0-9]{12}", principal_arn)
                            else principal_arn.split(":")[4]
                        )
                        principal_trusted = account_id in trusted_account_ids

                    access_from_trusted_accounts = (
                        principal_trusted or caller_condition_restrictive
                    )
                    report = Check_Report_AWS(
                        metadata=self.metadata(), resource=endpoint
                    )
                    if access_from_trusted_accounts:
                        report.status = "PASS"
                        report.status_extended = f"VPC Endpoint {endpoint.id} in VPC {endpoint.vpc_id} can only be accessed from trusted accounts."
                    else:
                        report.status = "FAIL"
                        report.status_extended = f"VPC Endpoint {endpoint.id} in VPC {endpoint.vpc_id} can be accessed from non-trusted accounts."
                    findings.append(report)

                    if not access_from_trusted_accounts:
                        break
                if not access_from_trusted_accounts:
                    break

        return findings
