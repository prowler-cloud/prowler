from re import compile

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.lib.policy import is_condition_block_restrictive
from prowler.providers.aws.services.vpc.vpc_client import vpc_client


def _is_condition_restrictive_for_trusted_accounts(
    condition_statement: dict, trusted_account_ids: set[str]
) -> bool:
    principal_account_values = []

    for operator in ("StringEquals", "StringLike"):
        for condition_key, condition_value in condition_statement.get(
            operator, {}
        ).items():
            if condition_key.lower() != "aws:principalaccount":
                continue

            if isinstance(condition_value, str):
                principal_account_values.append(condition_value)
            elif isinstance(condition_value, list):
                principal_account_values.extend(condition_value)
            else:
                return False

    if principal_account_values:
        return all(
            isinstance(account_id, str) and account_id in trusted_account_ids
            for account_id in principal_account_values
        )

    return all(
        is_condition_block_restrictive(condition_statement, account_id)
        for account_id in trusted_account_ids
    )


class vpc_endpoint_connections_trust_boundaries(Check):
    def execute(self):
        findings = []
        # Get trusted account_ids from prowler.config.yaml
        trusted_account_ids = set(
            vpc_client.audit_config.get("trusted_account_ids", [])
        )
        # Always include the same account as trusted
        trusted_account_ids.add(vpc_client.audited_account)
        for endpoint in vpc_client.vpc_endpoints:
            # Check VPC endpoint policy and  avoid "com.amazonaws.vpce" endpoints since the policy cannot be modified
            if (
                endpoint.policy_document
                and "com.amazonaws.vpce." not in endpoint.service_name
            ):
                access_from_trusted_accounts = True
                for statement in endpoint.policy_document["Statement"]:
                    # If one policy allows access from a non-trusted account
                    if not access_from_trusted_accounts:
                        break
                    if "*" == statement["Principal"]:
                        access_from_trusted_accounts = False
                        report = Check_Report_AWS(
                            metadata=self.metadata(), resource=endpoint
                        )

                        if "Condition" in statement:
                            access_from_trusted_accounts = (
                                _is_condition_restrictive_for_trusted_accounts(
                                    statement["Condition"], trusted_account_ids
                                )
                            )

                        if not access_from_trusted_accounts:
                            report.status = "FAIL"
                            report.status_extended = f"VPC Endpoint {endpoint.id} in VPC {endpoint.vpc_id} can be accessed from non-trusted accounts."
                        else:
                            report.status = "PASS"
                            report.status_extended = f"VPC Endpoint {endpoint.id} in VPC {endpoint.vpc_id} can only be accessed from trusted accounts."

                        findings.append(report)
                        if not access_from_trusted_accounts:
                            break

                    else:
                        if "AWS" in statement["Principal"]:
                            if isinstance(statement["Principal"]["AWS"], str):
                                principals = [statement["Principal"]["AWS"]]
                            else:
                                principals = statement["Principal"]["AWS"]
                        else:
                            # If the principal is not an AWS principal, we don't need to check it since it could be a service or a federated principal
                            principals = []
                        for principal_arn in principals:
                            report = Check_Report_AWS(
                                metadata=self.metadata(), resource=endpoint
                            )

                            if principal_arn == "*":
                                access_from_trusted_accounts = False
                                if "Condition" in statement:
                                    access_from_trusted_accounts = (
                                        _is_condition_restrictive_for_trusted_accounts(
                                            statement["Condition"],
                                            trusted_account_ids,
                                        )
                                    )

                                if not access_from_trusted_accounts:
                                    report.status = "FAIL"
                                    report.status_extended = f"VPC Endpoint {endpoint.id} in VPC {endpoint.vpc_id} can be accessed from non-trusted accounts."
                                else:
                                    report.status = "PASS"
                                    report.status_extended = f"VPC Endpoint {endpoint.id} in VPC {endpoint.vpc_id} can only be accessed from trusted accounts."

                                findings.append(report)
                                if not access_from_trusted_accounts:
                                    break
                            else:
                                # Account ID can be an ARN or just a 12-digit string
                                pattern = compile(r"^[0-9]{12}$")
                                match = pattern.match(principal_arn)
                                if not match:
                                    account_id = principal_arn.split(":")[4]
                                else:
                                    account_id = match.string

                                if account_id not in trusted_account_ids:
                                    access_from_trusted_accounts = False

                                if "Condition" in statement:
                                    access_from_trusted_accounts = (
                                        _is_condition_restrictive_for_trusted_accounts(
                                            statement["Condition"],
                                            trusted_account_ids,
                                        )
                                    )

                                if not access_from_trusted_accounts:
                                    report.status = "FAIL"
                                    report.status_extended = f"VPC Endpoint {endpoint.id} in VPC {endpoint.vpc_id} can be accessed from non-trusted accounts."
                                else:
                                    report.status = "PASS"
                                    report.status_extended = f"VPC Endpoint {endpoint.id} in VPC {endpoint.vpc_id} can only be accessed from trusted accounts."

                                findings.append(report)
                                if not access_from_trusted_accounts:
                                    break

        return findings
