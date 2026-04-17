from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.secretsmanager.secretsmanager_client import (
    secretsmanager_client,
)
from prowler.providers.aws.services.iam.lib.policy import is_condition_block_restrictive
import re


class secretsmanager_has_restrictive_resource_policy(Check):
    def execute(self):
        findings = []
        organizations_trusted_ids = secretsmanager_client.audit_config.get(
            "organizations_trusted_ids", []
        )
        # Regular expression to match IAM roles or users without wildcard * in their name
        arn_pattern = r"arn:aws:iam::\d{12}:(role|user)/([^*]+)$"
        # Regular expression to match AWS service names, including regionalized
        # and multi-label principals (e.g. logs.eu-central-1.amazonaws.com)
        service_pattern = r"^[a-z0-9-]+(\.[a-z0-9-]+)*\.amazonaws\.com$"
        # Regular expression to match any IAM ARN with account number
        iam_arn_with_account_pattern = r"arn:aws:iam::(\d{12}):"
        # Regular expression to match IAM root account ARN
        iam_root_arn_pattern = r"arn:aws:iam::(\d{12}):root"
        # Regular expression to match IAM role ARN with wildcard (at least 12 chars prefix before *)
        arn_wildcard_pattern = r"arn:aws:iam::\d{12}:role/.{12,}\*$"
        # Maximum number of cross-account principals to display in error messages
        max_principals_to_display = 3

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
                arn_not_like_principals = []  # Store ARN patterns from ArnNotLike

                # Check for an explicit Deny that applies to all Principals except those defined in the Condition
                has_explicit_deny_for_all = False

                # Track cross-account access detection
                cross_account_principals = []

                # Pass 1: Scan ALL Allow statements for cross-account principals
                # This must be a separate pass to ensure order-independent evaluation
                for statement in statements:
                    if statement.get("Effect") != "Allow":
                        continue
                    principals = self.extract_field(statement.get("Principal", {}))
                    for principal in principals:
                        if isinstance(principal, str):
                            match = re.match(iam_arn_with_account_pattern, principal)
                            if match:
                                principal_account = match.group(1)
                                if (
                                    principal_account
                                    != secretsmanager_client.audited_account
                                ):
                                    cross_account_principals.append(principal)
                            elif principal == "*" or re.match(
                                iam_root_arn_pattern, principal
                            ):
                                condition = statement.get("Condition", {})
                                if not condition or not is_condition_block_restrictive(
                                    condition,
                                    secretsmanager_client.audited_account,
                                    is_cross_account_allowed=False,
                                ):
                                    cross_account_principals.append(principal)

                # Pass 2: Validate Deny statements
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

                    # Check for ArnNotLike condition
                    arn_not_like_condition = {}
                    uses_arn_not_like = False
                    if "ArnNotLike" in condition:
                        arn_not_like_condition = condition.get("ArnNotLike", {})
                        uses_arn_not_like = "aws:PrincipalArn" in arn_not_like_condition

                    # Update valid keys to include ArnNotLike
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

                    # NEW: Validate ArnNotLike principals (must have at least 12 chars prefix before *)
                    if uses_arn_not_like:
                        arn_not_like_values = self.extract_field(
                            arn_not_like_condition.get("aws:PrincipalArn", [])
                        )
                        for arn in arn_not_like_values:
                            if not re.match(arn_wildcard_pattern, arn):
                                all_valid = False
                                break
                            arn_not_like_principals.append(arn)

                        if not all_valid:
                            continue

                    # STRICT VALIDATION: Check that no additional condition operators exist
                    # that could weaken the policy (e.g., StringNotLike, etc.)

                    # case 1: both keys for Principal and Service exist - require IfExists + Null Condition
                    if uses_principal_arn and uses_principal_service:
                        # Allow ArnNotLike as additional condition operator
                        allowed_condition_operators = {
                            "StringNotEqualsIfExists",
                            "Null",
                        }
                        if uses_arn_not_like:
                            allowed_condition_operators.add("ArnNotLike")

                        if (
                            set(condition.keys()) == allowed_condition_operators
                        ):  # STRICT: no additional operators
                            null_condition = condition.get("Null", {})
                            # STRICT: Null condition must have exactly these two keys with value "true"
                            if null_condition == {
                                "aws:PrincipalArn": "true",
                                "aws:PrincipalServiceName": "true",
                            }:
                                has_explicit_deny_for_all = True
                                break

                    # case 2: only PrincipalArn exists - require StringNotEquals (optionally with ArnNotLike)
                    elif uses_principal_arn and not uses_principal_service:
                        allowed_condition_operators = {"StringNotEquals"}
                        if uses_arn_not_like:
                            allowed_condition_operators.add("ArnNotLike")

                        if (
                            set(condition.keys()) == allowed_condition_operators
                        ):  # STRICT: no additional operators
                            has_explicit_deny_for_all = True
                            break

                # Check for ArnLike statement that validates the wildcard principals
                has_arn_like_validation = False
                if arn_not_like_principals:
                    arn_like_values = []
                    # Look for all statements with ArnLike condition because they must match all the ArnNotLike principals
                    for statement in statements:
                        if statement.get("Effect") == "Deny":
                            condition = statement.get("Condition", {})
                            if "ArnLike" in condition:
                                arn_like_condition = condition.get("ArnLike", {})
                                if "aws:PrincipalArn" in arn_like_condition:
                                    arn_like_value = self.extract_field(
                                        arn_like_condition.get("aws:PrincipalArn", [])
                                    )
                                    arn_like_values.extend(arn_like_value)
                                    # Check if all ArnNotLike principals are present in Deny-Statements with ArnLike Condition
                                    if set(arn_not_like_principals) == set(
                                        arn_like_values
                                    ):
                                        has_arn_like_validation = True
                                        break
                else:
                    # No ArnNotLike principals, so no validation needed
                    has_arn_like_validation = True

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
                        and len(statement["Condition"])
                        == 1  # STRICT: only StringNotEquals, no additional operators
                        and "StringNotEquals" in statement["Condition"]
                        and "aws:PrincipalOrgID"
                        in statement["Condition"]["StringNotEquals"]
                        and all(
                            v in organizations_trusted_ids
                            for v in self.extract_field(
                                statement["Condition"]["StringNotEquals"][
                                    "aws:PrincipalOrgID"
                                ]
                            )
                        )
                        # STRICT: validate that StringNotEquals keys match exactly what is expected
                        and (
                            (
                                not not_denied_services
                                and set(
                                    statement["Condition"]["StringNotEquals"].keys()
                                )
                                == {"aws:PrincipalOrgID"}
                            )
                            or (
                                not_denied_services
                                and set(
                                    statement["Condition"]["StringNotEquals"].keys()
                                )
                                == {"aws:PrincipalOrgID", "aws:PrincipalServiceName"}
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

                # Check for "NotActions" without wildcard * for not_denied_principals and not_denied_services.
                # NOTE: Per-principal Deny/NotAction statements are an OPTIONAL hardening layer.
                # The global Deny with StringNotEquals/aws:PrincipalArn already restricts access
                # to only listed principals. The per-principal NotAction blocks further limit what
                # each principal can do (defense-in-depth), but their absence does not cause a FAIL.
                # They are only validated IF present - wildcards in NotAction are rejected.
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
                                # Validate that the service-principal Allow statement
                                # has at least a "StringEquals" condition with "aws:SourceAccount".
                                # Additional restrictive conditions (e.g. ArnLike on aws:SourceArn) are acceptable.

                                # Collect specific issues for this service
                                issues = []
                                has_wildcard_action = any(
                                    "*" in action for action in actions
                                )
                                # Accept the condition if it contains at least
                                # StringEquals with aws:SourceAccount matching the
                                # audited account. Additional restrictive conditions
                                # (e.g. ArnLike on aws:SourceArn) are acceptable.
                                has_correct_condition = (
                                    "StringEquals" in condition
                                    and condition.get("StringEquals", {}).get(
                                        "aws:SourceAccount"
                                    )
                                    == secretsmanager_client.audited_account
                                )

                                if has_wildcard_action:
                                    issues.append("contains wildcard in Action field")
                                if not has_correct_condition:
                                    if not condition:
                                        issues.append("missing Condition block")
                                    else:
                                        issues.append(
                                            f"incorrect Condition (expected: StringEquals with aws:SourceAccount={secretsmanager_client.audited_account})"
                                        )

                                if issues:
                                    failed_services.append(
                                        {"service": service, "issues": issues}
                                    )

                has_specific_not_actions = len(failed_principals) == 0
                has_valid_service_policies = len(failed_services) == 0

                # Determine if the policy satisfies all conditions
                if (
                    not cross_account_principals  # No cross-account access via Allow statements
                    and has_explicit_deny_for_all
                    and has_deny_outside_org
                    and has_specific_not_actions
                    and has_valid_service_policies
                    and has_arn_like_validation
                ):
                    report.status = "PASS"
                    report.status_extended = f"SecretsManager secret '{secret.name}' has a sufficiently restrictive resource-based policy."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"SecretsManager secret '{secret.name}' does not meet all required restrictions: "

                    # Append detailed reasons for each failed condition
                    if cross_account_principals:
                        report.status_extended += (
                            f"Cross-account access detected - the following external principals have access: "
                            f"{', '.join(cross_account_principals[:max_principals_to_display])}"
                            f"{' and more...' if len(cross_account_principals) > max_principals_to_display else ''}. "
                        )

                    if not has_explicit_deny_for_all:
                        # Build a helpful error message showing which principals are expected
                        expected_parts = []

                        # Case 1: Only PrincipalArn exists → StringNotEquals
                        if not_denied_principals and not not_denied_services:
                            principals_str = ", ".join(
                                not_denied_principals[:max_principals_to_display]
                            )
                            if len(not_denied_principals) > max_principals_to_display:
                                principals_str += " and more..."
                            expected_parts.append(
                                f"StringNotEquals with aws:PrincipalArn: {principals_str}"
                            )

                        # Case 2: Both PrincipalArn and PrincipalServiceName exist → StringNotEqualsIfExists + Null
                        elif not_denied_principals and not_denied_services:
                            principals_str = ", ".join(
                                not_denied_principals[:max_principals_to_display]
                            )
                            if len(not_denied_principals) > max_principals_to_display:
                                principals_str += " and more..."
                            services_str = ", ".join(
                                not_denied_services[:max_principals_to_display]
                            )
                            if len(not_denied_services) > max_principals_to_display:
                                services_str += " and more..."
                            expected_parts.append(
                                f"StringNotEqualsIfExists with aws:PrincipalArn: {principals_str} and "
                                f"aws:PrincipalServiceName: {services_str}, plus Null condition for both keys with value 'true'"
                            )

                        # Case 3: Only PrincipalServiceName exists (edge case should never happen, but handle it)
                        elif not_denied_services and not not_denied_principals:
                            services_str = ", ".join(
                                not_denied_services[:max_principals_to_display]
                            )
                            if len(not_denied_services) > max_principals_to_display:
                                services_str += " and more..."
                            expected_parts.append(
                                f"StringNotEqualsIfExists with aws:PrincipalServiceName: {services_str}"
                            )

                        # Add ArnNotLike information if present
                        if arn_not_like_principals:
                            arns_str = ", ".join(
                                arn_not_like_principals[:max_principals_to_display]
                            )
                            if len(arn_not_like_principals) > max_principals_to_display:
                                arns_str += " and more..."
                            expected_parts.append(
                                f"ArnNotLike with aws:PrincipalArn: {arns_str}"
                            )

                        if expected_parts:
                            report.status_extended += f"Missing or incorrect 'Deny' statement for all Principals (expected conditions: {'; '.join(expected_parts)}). "
                        else:
                            report.status_extended += "Missing or incorrect 'Deny' statement for all Principals. "

                    if not has_deny_outside_org:
                        if not_denied_services:
                            report.status_extended += (
                                f"Missing or incorrect 'Deny' statement restricting access outside 'PrincipalOrgID'. "
                                f"The statement must also include 'aws:PrincipalServiceName' in StringNotEquals condition "
                                f"with the following service(s): {not_denied_services}. "
                            )
                        else:
                            report.status_extended += "Missing or incorrect 'Deny' statement restricting access outside 'PrincipalOrgID'. "

                    if not has_specific_not_actions:
                        report.status_extended += f"Missing field 'NotAction' or disallowed wildcard * in the 'NotAction' field of the 'Deny' statement for the specific Principal(s) {failed_principals if failed_principals else ''}. "

                    if not has_valid_service_policies:
                        # Build detailed error message for each failed service
                        service_errors = []
                        for failed_service in failed_services[
                            :max_principals_to_display
                        ]:
                            service_name = failed_service["service"]
                            issues_str = ", ".join(failed_service["issues"])
                            service_errors.append(f"{service_name} ({issues_str})")

                        if len(failed_services) > max_principals_to_display:
                            remaining = len(failed_services) - max_principals_to_display
                            service_errors.append(f"and {remaining} more...")

                        report.status_extended += f"Invalid 'Allow' statements for Service Principals: {'; '.join(service_errors)}. "

                    if not has_arn_like_validation:
                        report.status_extended += f"Missing or incorrect 'ArnLike' validation statement for wildcard principals {arn_not_like_principals}. "

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
