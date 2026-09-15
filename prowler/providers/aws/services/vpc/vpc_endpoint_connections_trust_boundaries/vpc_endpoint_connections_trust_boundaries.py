from fnmatch import fnmatchcase
from re import compile

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.lib.policy import is_condition_block_restrictive
from prowler.providers.aws.services.vpc.vpc_client import vpc_client


def _is_condition_restrictive_for_trusted_accounts(
    condition_statement: dict, trusted_account_ids: set[str]
) -> bool:
    principal_account_groups = []
    remaining_conditions = {}

    for operator, conditions in condition_statement.items():
        remaining_operator_conditions = {}
        for condition_key, condition_value in conditions.items():
            if (
                operator in ("StringEquals", "StringLike")
                and condition_key.lower() == "aws:principalaccount"
            ):
                if isinstance(condition_value, str):
                    values = [condition_value]
                elif isinstance(condition_value, list) and all(
                    isinstance(value, str) for value in condition_value
                ):
                    values = condition_value
                else:
                    values = []

                principal_account_groups.append((operator, values))
            else:
                remaining_operator_conditions[condition_key] = condition_value

        if remaining_operator_conditions:
            remaining_conditions[operator] = remaining_operator_conditions

    principal_account_restrictive = False
    if principal_account_groups:
        exact_groups = [
            set(values)
            for operator, values in principal_account_groups
            if operator == "StringEquals"
        ]
        if exact_groups:
            possible_accounts = set.intersection(*exact_groups)
        else:
            literal_groups = [
                set(values)
                for _, values in principal_account_groups
                if all(
                    not any(character in value for character in "*?[")
                    for value in values
                )
            ]
            possible_accounts = (
                set.intersection(*literal_groups) if literal_groups else None
            )

        if possible_accounts is not None:
            for operator, values in principal_account_groups:
                if operator == "StringLike":
                    possible_accounts = {
                        account_id
                        for account_id in possible_accounts
                        if any(fnmatchcase(account_id, pattern) for pattern in values)
                    }

            principal_account_restrictive = possible_accounts.issubset(
                trusted_account_ids
            )

    remaining_conditions_restrictive = remaining_conditions and any(
        is_condition_block_restrictive(remaining_conditions, account_id)
        for account_id in trusted_account_ids
    )

    return bool(principal_account_restrictive or remaining_conditions_restrictive)


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
