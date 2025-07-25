from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.secretsmanager.secretsmanager_client import (
    secretsmanager_client,
)
import re


class secretsmanager_has_restrictive_resource_policy(Check):
    def execute(self):
        findings = []
        organizations_trusted_ids = secretsmanager_client.audit_config.get(
            "organizations_trusted_ids", []
        )
        # Regular expression to match IAM roles or users without wildcard * in their name
        arn_pattern = r"arn:aws:iam::\d{12}:(role|user)/([^*]+)$"
        # Regular expression to match AWS service names
        service_pattern = r"^[a-z0-9-]+\.amazonaws\.com$"

        for secret in secretsmanager_client.secrets.values():
            report = Check_Report_AWS(self.metadata(), resource=secret)
            report.region = secret.region
            report.resource_id = secret.name
            report.resource_arn = secret.arn
            report.resource_tags = secret.tags
            report.status = "FAIL"
            # Determine the Role ARN to be used
            assumed_role_config = getattr(
                secretsmanager_client.provider, "_assumed_role_configuration", None
            )
            if (
                assumed_role_config
                and getattr(assumed_role_config, "info", None)
                and getattr(assumed_role_config.info, "role_arn", None)
                and getattr(assumed_role_config.info.role_arn, "arn", None)
            ):
                final_role_arn = assumed_role_config.info.role_arn.arn
            else:
                identity_arn = secretsmanager_client.provider.identity.identity_arn
                if identity_arn:
                    # If the identity ARN is a sts assumed-role ARN, transform it
                    match = re.match(
                        r"arn:aws:sts::(\d+):assumed-role/([^/]+)/", identity_arn
                    )
                    if match:
                        account_id, role_name = match.groups()
                        final_role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
                    else:
                        final_role_arn = identity_arn
                else:
                    final_role_arn = "None"

            report.status_extended = (
                f"SecretsManager secret '{secret.name}' does not have a resource-based policy "
                f"or access to the policy is denied for the role '{final_role_arn}'"
            )

            if secret.policy:
                statements = secret.policy.get("Statement", [])
                not_denied_principals = []
                not_denied_services = []

                # Check for an explicit Deny that applies to all Principals except those defined in the Condition
                has_explicit_deny_for_all = False

                for statement in statements:
                    if statement.get("Effect") != "Deny":
                        continue
                    principal = self.extract_field(statement.get("Principal", {}))
                    if "*" not in principal:
                        continue
                    actions = self.extract_field(statement.get("Action", []))
                    if not any(
                        action in ["*", "secretsmanager:*"] for action in actions
                    ):
                        continue
                    if not self.is_valid_resource(
                        secret, self.extract_field(statement.get("Resource", "*"))
                    ):
                        continue

                    condition = statement.get("Condition", {})

                    condition_principals = {}
                    if "StringNotEquals" in condition:
                        condition_principals = condition.get("StringNotEquals", {})
                    elif "StringNotEqualsIfExists" in condition:
                        condition_principals = condition.get(
                            "StringNotEqualsIfExists", {}
                        )

                    uses_principal_arn = "aws:PrincipalArn" in condition_principals
                    uses_principal_service = (
                        "aws:PrincipalServiceName" in condition_principals
                    )

                    valid_keys = {"aws:PrincipalArn", "aws:PrincipalServiceName"}
                    if not set(condition_principals.keys()).issubset(valid_keys):
                        continue

                    # check values of principals
                    all_valid = True
                    for key, (not_denied_list, pattern) in {
                        "aws:PrincipalArn": (not_denied_principals, arn_pattern),
                        "aws:PrincipalServiceName": (
                            not_denied_services,
                            service_pattern,
                        ),
                    }.items():
                        if key in condition_principals:
                            if not self.is_valid_principal(
                                condition_principals[key], not_denied_list, pattern
                            ):
                                all_valid = False
                                break

                    if not all_valid:
                        continue

                    # case 1: both keys for Principal and Service exist → require IfExists + Null Condition
                    if uses_principal_arn and uses_principal_service:
                        if (
                            "StringNotEqualsIfExists" in condition
                            and "Null" in condition
                        ):
                            null_condition = condition.get("Null", {})
                            if (
                                null_condition.get("aws:PrincipalArn") == "true"
                                and null_condition.get("aws:PrincipalServiceName")
                                == "true"
                            ):
                                has_explicit_deny_for_all = True
                                break

                    # case 2: only PrincipalArn exists → require StringNotEquals
                    elif uses_principal_arn and not uses_principal_service:
                        if "StringNotEquals" in condition:
                            has_explicit_deny_for_all = True
                            break

                # Check for Deny with "StringNotEquals":"aws:PrincipalOrgID" condition
                has_deny_outside_org = (
                    True
                    if not organizations_trusted_ids
                    else any(
                        statement.get("Effect") == "Deny"
                        and "*" in self.extract_field(statement.get("Principal", {}))
                        and any(
                            action in ["*", "secretsmanager:*"]
                            for action in self.extract_field(
                                statement.get("Action", [])
                            )
                        )
                        and self.is_valid_resource(
                            secret, self.extract_field(statement.get("Resource", "*"))
                        )
                        and "Condition" in statement
                        and set(statement["Condition"].keys()) == {"StringNotEquals"}
                        and (
                            (
                                set(statement["Condition"]["StringNotEquals"].keys())
                                == {"aws:PrincipalOrgID"}
                                and all(
                                    v in organizations_trusted_ids
                                    for v in self.extract_field(
                                        statement["Condition"]["StringNotEquals"][
                                            "aws:PrincipalOrgID"
                                        ]
                                    )
                                )
                            )
                            if not not_denied_services
                            else (
                                set(statement["Condition"]["StringNotEquals"].keys())
                                == {"aws:PrincipalOrgID", "aws:PrincipalServiceName"}
                                and all(
                                    v in organizations_trusted_ids
                                    for v in self.extract_field(
                                        statement["Condition"]["StringNotEquals"][
                                            "aws:PrincipalOrgID"
                                        ]
                                    )
                                )
                                and all(
                                    s in not_denied_services
                                    for s in self.extract_field(
                                        statement["Condition"]["StringNotEquals"][
                                            "aws:PrincipalServiceName"
                                        ]
                                    )
                                )
                            )
                        )
                        for statement in statements
                    )
                )

                # Check for "NotActions" without wildcard * for not_denied_principals and not_denied_services
                failed_principals = []
                failed_services = []

                # Validate that NotAction does not contain wildcards for specified principals
                for statement in statements:
                    if statement.get("Effect") == "Deny":
                        principals = self.extract_field(statement.get("Principal", {}))

                        # Check "NotAction" of Deny statements only for not_denied_principals
                        for principal in principals:
                            if principal in not_denied_principals:
                                if "NotAction" not in statement or any(
                                    "*" in action
                                    for action in self.extract_field(
                                        statement.get("NotAction", [])
                                    )
                                ):
                                    failed_principals.append(principal)

                # Allow-Statement for not-denied services must not have any wildcards in "Action"
                # and "SourceAccount" must be the audited account
                for statement in statements:
                    if statement.get("Effect") == "Allow":
                        principals = self.extract_field(statement.get("Principal", {}))
                        for service in principals:
                            if service in not_denied_services:
                                condition = statement.get("Condition", {})
                                actions = self.extract_field(
                                    statement.get("Action", [])
                                )
                                if (
                                    "StringEquals" not in condition
                                    or condition.get("StringEquals", {}).get(
                                        "aws:SourceAccount"
                                    )
                                    != secretsmanager_client.audited_account
                                    or len(condition)
                                    > 1  # only "StringEquals" is allowed
                                    or any("*" in action for action in actions)
                                ):  # wildcard in "Action" is not allowed
                                    failed_services.append(service)

                has_specific_not_actions = len(failed_principals) == 0
                has_valid_service_policies = len(failed_services) == 0

                # Determine if the policy satisfies all conditions
                if (
                    has_explicit_deny_for_all
                    and has_deny_outside_org
                    and has_specific_not_actions
                    and has_valid_service_policies
                ):
                    report.status = "PASS"
                    report.status_extended = f"SecretsManager secret '{secret.name}' has a sufficiently restrictive resource-based policy."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"SecretsManager secret '{secret.name}' does not meet all required restrictions: "
                    if not has_explicit_deny_for_all:
                        report.status_extended += "Missing or incorrect 'Deny' statement for all Principals with wildcard Action. "
                    if not has_deny_outside_org:
                        report.status_extended += "Missing or incorrect 'Deny' statement restricting access outside 'PrincipalOrgID'. "
                    if not has_specific_not_actions:
                        report.status_extended += f"Missing field 'NotAction' or disallowed wildcard * in the 'NotAction' field of the 'Deny' statement for the specific Principal(s) {failed_principals if failed_principals else ''}. "
                    if not has_valid_service_policies:
                        report.status_extended += f"Invalid 'Allow' statements for Service Principals {failed_services if failed_services else ''}. "

            findings.append(report)

        return findings

    # Extract values from a field to return an array containing the field,
    # handling single values, arrays and dict with keys "AWS" or "Service".
    # If the field is empty or invalid, return the default_value in the array.
    def extract_field(self, field, default_value=None):
        if isinstance(field, str):
            return [field]
        elif isinstance(field, list):
            return field
        elif isinstance(field, dict):
            for key in ("AWS", "Service"):
                if key in field:
                    return [field[key]] if isinstance(field[key], str) else field[key]
        return [default_value]

    def is_valid_resource(self, secret, resource):
        """Check if the Resource field is valid for the given secret."""
        if resource == "*":
            return True  # Wildcard resource is acceptable in general cases
        if isinstance(resource, list):
            if "*" in resource:
                return True
            return all(r == secret.arn for r in resource)
        return resource == secret.arn

    def is_valid_principal(self, principal_value, not_denied_list, pattern):
        if not_denied_list is None or pattern is None:
            return False

        principals = self.extract_field(principal_value)
        for principal in principals:
            if re.match(pattern, principal):
                not_denied_list.append(principal)
            else:
                return False

        return True
