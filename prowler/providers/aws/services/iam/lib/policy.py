import re
from ipaddress import ip_address, ip_network
from typing import Optional, Tuple

from py_iam_expand.actions import InvalidActionHandling, expand_actions

from prowler.lib.logger import logger
from prowler.providers.aws.aws_provider import read_aws_regions_file


def _get_patterns_from_standard_value(value):
    """
    Helper function to process standard action/notaction values.
    Accepts a string or list of strings and returns a set of string patterns.
    """
    patterns = set()
    if isinstance(value, str):
        patterns.add(value)
    elif isinstance(value, list):
        patterns.update(item for item in value if isinstance(item, str))
    return patterns


def get_effective_actions(policy: dict) -> set[str]:
    """
    Calculates the set of effectively allowed IAM actions from a policy document.

    This function considers Allow/Deny effects, Action/NotAction fields,
    expands wildcards, handles invalid NotAction patterns correctly,
    and applies the Deny > Allow precedence. Assumes standard AWS policy
    format where Action/NotAction is a string or a list of strings.

    Args:
        policy (dict): The IAM policy document.

    Returns:
        set[str]: A set of effectively allowed IAM action strings.
    """
    if not policy or "Statement" not in policy:
        return set()

    directly_allowed_actions = set()
    directly_denied_actions = set()
    allow_not_action_exclusions = set()
    deny_not_action_exclusions = set()
    has_allow_not_action_statement = False
    has_deny_not_action_statement = False

    statements = policy.get("Statement", [])
    if not isinstance(statements, list):
        statements = [statements]

    for statement in statements:
        effect = statement.get("Effect", "")
        if not isinstance(effect, str):
            continue
        effect = effect.strip().lower()

        if effect not in ["allow", "deny"]:
            continue

        actions = statement.get("Action")
        not_actions = statement.get("NotAction")

        action_patterns_to_expand = _get_patterns_from_standard_value(actions)
        if action_patterns_to_expand:
            expanded = set()
            for pattern in action_patterns_to_expand:
                expanded.update(
                    expand_actions(
                        pattern,
                        InvalidActionHandling.REMOVE,
                    )
                )
            if effect == "allow":
                directly_allowed_actions.update(expanded)
            else:  # deny
                directly_denied_actions.update(expanded)

        not_action_patterns_to_expand = _get_patterns_from_standard_value(not_actions)
        if not_action_patterns_to_expand:
            expanded_exclusions = set()
            for pattern in not_action_patterns_to_expand:
                expanded_exclusions.update(
                    expand_actions(
                        pattern,
                        InvalidActionHandling.REMOVE,
                    )
                )
            if effect == "allow":
                allow_not_action_exclusions.update(expanded_exclusions)
                has_allow_not_action_statement = True
            else:  # deny
                deny_not_action_exclusions.update(expanded_exclusions)
                has_deny_not_action_statement = True

    all_actions = None

    # Actions allowed by "Allow Action" statements
    potentially_allowed = directly_allowed_actions

    # Actions allowed by "Allow NotAction" statements
    if has_allow_not_action_statement:
        if all_actions is None:
            all_actions = set(
                expand_actions(
                    "*",
                    InvalidActionHandling.REMOVE,
                )
            )
        allowed_by_not_action = all_actions.difference(allow_not_action_exclusions)
        potentially_allowed.update(allowed_by_not_action)

    # Actions denied by "Deny Action" statements
    potentially_denied = directly_denied_actions

    # Actions denied by "Deny NotAction" statements
    if has_deny_not_action_statement:
        if all_actions is None:
            all_actions = set(
                expand_actions(
                    "*",
                    InvalidActionHandling.REMOVE,
                )
            )
        denied_by_not_action = all_actions.difference(deny_not_action_exclusions)
        potentially_denied.update(denied_by_not_action)

    effective_actions = potentially_allowed.difference(potentially_denied)

    return effective_actions


def check_full_service_access(service: str, policy: dict) -> bool:
    """
    Determines if a policy grants full access to a specific AWS service
    on all resources ("*").

    Args:
        service (str): The AWS service name (e.g., 's3', 'ec2', or '*' for admin).
        policy (dict): The IAM policy document.

    Returns:
        bool: True if full access on all resources is granted, False otherwise.
    """
    if not policy or "Statement" not in policy:
        return False

    service_wildcard = f"{service}:*" if service != "*" else "*"
    all_target_service_actions = set(
        expand_actions(
            service_wildcard,
            InvalidActionHandling.REMOVE,
        )
    )

    effective_allowed_actions = get_effective_actions(policy)

    if not all_target_service_actions.issubset(effective_allowed_actions):
        return False

    actions_allowed_on_all_resources = set()
    statements = policy.get("Statement", [])
    if not isinstance(statements, list):
        statements = [statements]

    all_aws_actions_for_inversion = None

    for statement in statements:
        effect = statement.get("Effect", "")
        resources = statement.get("Resource", [])

        if not isinstance(effect, str) or effect.strip().lower() != "allow":
            continue
        if isinstance(resources, str):
            resources = [resources]
        if "*" not in resources:
            continue

        actions = statement.get("Action")
        not_actions = statement.get("NotAction")
        statement_specific_allowed = set()

        # Use the shared helper function instead of the duplicated one
        action_patterns = _get_patterns_from_standard_value(actions)
        for pattern in action_patterns:
            statement_specific_allowed.update(
                expand_actions(
                    pattern,
                    InvalidActionHandling.REMOVE,
                )
            )

        not_action_patterns = _get_patterns_from_standard_value(not_actions)
        if not_action_patterns:
            if all_aws_actions_for_inversion is None:
                all_aws_actions_for_inversion = set(
                    expand_actions(
                        "*",
                        InvalidActionHandling.REMOVE,
                    )
                )

            statement_exclusions = set()
            for pattern in not_action_patterns:
                statement_exclusions.update(
                    expand_actions(
                        pattern,
                        InvalidActionHandling.REMOVE,
                    )
                )
            # Actions allowed by THIS NotAction statement
            statement_specific_allowed.update(
                all_aws_actions_for_inversion.difference(statement_exclusions)
            )

        actions_allowed_on_all_resources.update(
            action
            for action in statement_specific_allowed
            if action in all_target_service_actions
        )

    return all_target_service_actions.issubset(actions_allowed_on_all_resources)


def has_public_principal(statement: dict) -> bool:
    """
    Check if a policy statement has a public principal.

    Args:
        statement (dict): IAM policy statement

    Returns:
        bool: True if the statement has a public principal, False otherwise
    """
    principal = statement.get("Principal", "")
    return (
        "*" in principal
        or "arn:aws:iam::*:root" in principal
        or (
            isinstance(principal, dict)
            and (
                "*" in principal.get("AWS", "")
                or "arn:aws:iam::*:root" in principal.get("AWS", "")
                or (
                    isinstance(principal.get("AWS"), list)
                    and (
                        "*" in principal["AWS"]
                        or "arn:aws:iam::*:root" in principal["AWS"]
                    )
                )
                or "*" in principal.get("CanonicalUser", "")
                or "arn:aws:iam::*:root" in principal.get("CanonicalUser", "")
            )
        )
    )


def has_restrictive_source_arn_condition(
    statement: dict, source_account: str = ""
) -> bool:
    """
    Check if a policy statement has a restrictive aws:SourceArn condition.

    A SourceArn condition is considered restrictive if:
    1. It doesn't contain overly permissive wildcards (like "*" or "arn:aws:s3:::*")
    2. When source_account is provided, the ARN either contains no account field (like S3 buckets)
       or contains the source_account

    Args:
        statement (dict): IAM policy statement
        source_account (str): The account to check restrictions for (optional)

    Returns:
        bool: True if the statement has a restrictive aws:SourceArn condition, False otherwise
    """
    if "Condition" not in statement:
        return False

    for condition_operator in statement["Condition"]:
        for condition_key, condition_value in statement["Condition"][
            condition_operator
        ].items():
            if condition_key.lower() == "aws:sourcearn":
                arn_values = (
                    condition_value
                    if isinstance(condition_value, list)
                    else [condition_value]
                )

                for arn_value in arn_values:
                    if (
                        arn_value == "*"  # Global wildcard
                        or arn_value.count("*")
                        >= 3  # Too many wildcards (e.g., arn:aws:*:*:*:*)
                        or (
                            isinstance(arn_value, str)
                            and (
                                arn_value.endswith(
                                    ":::*"
                                )  # Service-wide wildcard (e.g., arn:aws:s3:::*)
                                or arn_value.endswith(
                                    ":*"
                                )  # Resource wildcard (e.g., arn:aws:sns:us-east-1:123456789012:*)
                            )
                        )
                    ):
                        return False

                    if source_account:
                        arn_parts = arn_value.split(":")
                        if len(arn_parts) > 4 and arn_parts[4] and arn_parts[4] != "*":
                            if arn_parts[4].isdigit():
                                if source_account not in arn_value:
                                    return False
                            else:
                                if arn_parts[4] != source_account:
                                    return False
                        elif len(arn_parts) > 4 and arn_parts[4] == "*":
                            return False
                        # else: ARN doesn't contain account field (like S3 bucket), so it's restrictive

                return True

    return False


def is_condition_restricting_from_private_ip(condition_statement: dict) -> bool:
    """Check if the policy condition is coming from a private IP address.

    Keyword arguments:
    condition_statement -- The policy condition to check. For example:
        {
            "IpAddress": {
                "aws:SourceIp": "X.X.X.X"
            }
        }
    """
    try:
        CONDITION_OPERATOR = "IpAddress"
        CONDITION_KEY = "aws:sourceip"

        is_from_private_ip = False

        if condition_statement.get(CONDITION_OPERATOR, {}):
            # We need to transform the condition_statement into lowercase
            condition_statement[CONDITION_OPERATOR] = {
                k.lower(): v for k, v in condition_statement[CONDITION_OPERATOR].items()
            }

            if condition_statement[CONDITION_OPERATOR].get(CONDITION_KEY, ""):
                if not isinstance(
                    condition_statement[CONDITION_OPERATOR][CONDITION_KEY], list
                ):
                    condition_statement[CONDITION_OPERATOR][CONDITION_KEY] = [
                        condition_statement[CONDITION_OPERATOR][CONDITION_KEY]
                    ]

                for ip in condition_statement[CONDITION_OPERATOR][CONDITION_KEY]:
                    # Select if IP address or IP network searching in the string for '/'
                    if ip == "*" or ip == "0.0.0.0/0":
                        break
                    else:
                        if "/" in ip:
                            if not ip_network(ip, strict=False).is_private:
                                break
                        else:
                            if not ip_address(ip).is_private:
                                break
                else:
                    is_from_private_ip = True

    except ValueError:
        logger.error(f"Invalid IP: {ip}")
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )

    return is_from_private_ip


# TODO: Add logic for deny statements
def is_policy_public(
    policy: dict,
    source_account: str = "",
    is_cross_account_allowed=True,
    not_allowed_actions: list = [],
    check_cross_service_confused_deputy=False,
    trusted_account_ids: list = None,
) -> bool:
    """
    Check if the policy allows public access to the resource.
    If the policy gives access to an AWS service principal is considered public if the policy is not pair with conditions since it can be invoked by AWS services in other accounts.
    Args:
        policy (dict): The AWS policy to check
        source_account (str): The account to check if the access is restricted to it, default: ""
        is_cross_account_allowed (bool): If the policy can allow cross-account access, default: True (https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html#cross-service-confused-deputy-prevention)
        not_allowed_actions (list): List of actions that are not allowed, default: []. If not_allowed_actions is empty, the function will not consider the actions in the policy.
        check_cross_service_confused_deputy (bool): If the policy is checked for cross-service confused deputy, default: False
        trusted_account_ids (list): A list of trusted accound ids to reduce false positives on cross-account checks
    Returns:
        bool: True if the policy allows public access, False otherwise
    """
    is_public = False

    if trusted_account_ids is None:
        trusted_account_ids = []

    trusted_accounts = set(trusted_account_ids)
    if source_account:
        trusted_accounts.add(source_account)

    if policy:
        for statement in policy.get("Statement", []):
            # Only check allow statements
            if statement["Effect"] == "Allow":
                has_public_access = has_public_principal(statement)

                principal = statement.get("Principal", "")
                if not has_public_access and isinstance(principal, dict):
                    # Check for cross-account access when not allowed
                    if (
                        isinstance(principal.get("AWS"), str)
                        and source_account
                        and not is_cross_account_allowed
                        and not any(
                            trusted_account in principal.get("AWS", "")
                            for trusted_account in trusted_accounts
                        )
                    ) or (
                        isinstance(principal.get("AWS"), list)
                        and source_account
                        and not is_cross_account_allowed
                        and not all(
                            any(
                                trusted_account in principal_aws
                                for trusted_account in trusted_accounts
                            )
                            for principal_aws in principal["AWS"]
                        )
                    ):
                        has_public_access = True

                    # Check for cross-service confused deputy
                    if check_cross_service_confused_deputy:
                        # Check if function can be invoked by other AWS services if check_cross_service_confused_deputy is True

                        svc = principal.get("Service", [])
                        if isinstance(svc, str):
                            services = [svc]
                        elif isinstance(svc, list):
                            services = [s for s in svc if isinstance(s, str)]
                        else:
                            services = []

                        is_cross_service = any(
                            s == "*"
                            or s.endswith(".amazonaws.com")
                            or s.endswith(".amazon.com")
                            for s in services
                        )

                        # AWS ensures that resources called by SecretsManager are executed in the same AWS account
                        # AWS ensures that resources called by EKS are executed in the same AWS account
                        is_exempt = any(
                            s in {"secretsmanager.amazonaws.com", "eks.amazonaws.com"}
                            for s in services
                        )

                        if is_cross_service and not is_exempt:
                            has_public_access = True

                if has_public_access and (
                    not not_allowed_actions  # If not_allowed_actions is empty, the function will not consider the actions in the policy
                    or (
                        statement.get(
                            "Action"
                        )  # If the statement has no action, it is not public
                        and (
                            (
                                (
                                    isinstance(statement.get("Action", ""), list)
                                    and "*" in statement["Action"]
                                )
                                or (
                                    isinstance(statement.get("Action", ""), str)
                                    and statement.get("Action", "") == "*"
                                )
                            )
                            or (
                                isinstance(statement.get("Action", ""), list)
                                and any(
                                    action in not_allowed_actions
                                    for action in statement["Action"]
                                )
                            )
                            or (statement.get("Action", "") in not_allowed_actions)
                        )
                    )
                ):
                    is_public = not statement.get("Condition", {}) or (
                        not is_condition_block_restrictive(
                            statement.get("Condition", {}),
                            source_account,
                            is_cross_account_allowed,
                        )
                        and not is_condition_block_restrictive_organization(
                            statement.get("Condition", {})
                        )
                        and not is_condition_restricting_from_private_ip(
                            statement.get("Condition", {})
                        )
                    )
                    if is_public:
                        break
    return is_public


def is_condition_block_restrictive(
    condition_statement: dict,
    source_account: str = "",
    is_cross_account_allowed=False,
):
    """
    is_condition_block_restrictive parses the IAM Condition policy block and, by default, returns True if the source_account passed as argument is within, False if not.

    If argument is_cross_account_allowed is True it tests if the Condition block includes any of the operators allowlisted returning True if does, False if not.

    Args:
        condition_statement: dict with an IAM Condition block, e.g.:
        {
            "StringLike": {
                "AWS:SourceAccount": 111122223333
            }
        }

        source_account: str with a 12-digit AWS Account number, e.g.: 111122223333, default: ""

        is_cross_account_allowed: bool to allow cross-account access, e.g.: True, default: False

    """
    is_condition_valid = False

    # The conditions must be defined in lowercase since the context key names are not case-sensitive.
    # For example, including the aws:SourceAccount context key is equivalent to testing for AWS:SourceAccount
    # https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition.html
    valid_condition_options = {
        "StringEquals": [
            "aws:sourceaccount",
            "aws:sourceowner",
            "aws:sourcearn",
            "aws:principalaccount",
            "aws:principalarn",
            "aws:principalorgid",
            "aws:principalorgpaths",
            "aws:resourceaccount",
            "aws:sourcevpc",
            "aws:sourcevpce",
            "aws:sourceorgid",
            "aws:sourceorgpaths",
            "aws:userid",
            "aws:username",
            "s3:resourceaccount",
            "lambda:eventsourcetoken",  # For Alexa Home functions, a token that the invoker must supply.
        ],
        "StringLike": [
            "aws:sourceaccount",
            "aws:sourceowner",
            "aws:sourcearn",
            "aws:principalaccount",
            "aws:principalarn",
            "aws:principalorgid",
            "aws:principalorgpaths",
            "aws:resourceaccount",
            "aws:sourcevpc",
            "aws:sourcevpce",
            "aws:sourceorgid",
            "aws:sourceorgpaths",
            "aws:userid",
            "aws:username",
            "s3:resourceaccount",
            "lambda:eventsourcetoken",
        ],
        "ArnLike": ["aws:sourcearn", "aws:principalarn"],
        "ArnEquals": ["aws:sourcearn", "aws:principalarn"],
    }

    for condition_operator, condition_operator_key in valid_condition_options.items():
        if condition_operator in condition_statement:
            for value in condition_operator_key:
                # We need to transform the condition_statement into lowercase
                condition_statement[condition_operator] = {
                    k.lower(): v
                    for k, v in condition_statement[condition_operator].items()
                }

                if value in condition_statement[condition_operator]:
                    # values are a list
                    if isinstance(
                        condition_statement[condition_operator][value],
                        list,
                    ):
                        is_condition_key_restrictive = True
                        # if cross account is not allowed check for each condition block looking for accounts
                        # different than default
                        if not is_cross_account_allowed:
                            # if there is an arn/account without the source account -> we do not consider it safe
                            # here by default we assume is true and look for false entries
                            for item in condition_statement[condition_operator][value]:
                                if (
                                    "aws:sourcevpc" != value
                                    and "aws:sourcevpce" != value
                                ):
                                    if value == "aws:sourcearn":
                                        # Use the specialized function to properly validate SourceArn restrictions
                                        # Create a minimal statement to test with our function
                                        test_statement = {
                                            "Condition": {
                                                condition_operator: {
                                                    value: condition_statement[
                                                        condition_operator
                                                    ][value]
                                                }
                                            }
                                        }
                                        is_condition_key_restrictive = (
                                            has_restrictive_source_arn_condition(
                                                test_statement, source_account
                                            )
                                        )
                                        if not is_condition_key_restrictive:
                                            break
                                    else:
                                        if source_account not in item:
                                            is_condition_key_restrictive = False
                                            break

                        if is_condition_key_restrictive:
                            is_condition_valid = True

                    # value is a string
                    elif isinstance(
                        condition_statement[condition_operator][value],
                        str,
                    ):
                        if "aws:sourcevpc" == value or "aws:sourcevpce" == value:
                            is_condition_valid = True
                        else:
                            if is_cross_account_allowed:
                                is_condition_valid = True
                            else:
                                if value == "aws:sourcearn":
                                    # Use the specialized function to properly validate SourceArn restrictions
                                    # Create a minimal statement to test with our function
                                    test_statement = {
                                        "Condition": {
                                            condition_operator: {
                                                value: condition_statement[
                                                    condition_operator
                                                ][value]
                                            }
                                        }
                                    }
                                    is_condition_valid = (
                                        has_restrictive_source_arn_condition(
                                            test_statement, source_account
                                        )
                                    )
                                else:
                                    if (
                                        source_account
                                        in condition_statement[condition_operator][
                                            value
                                        ]
                                    ):
                                        is_condition_valid = True

    return is_condition_valid


def is_condition_block_restrictive_organization(
    condition_statement: dict,
):
    """
    is_condition_block_restrictive_organization parses the IAM Condition policy block and returns True if the condition_statement is restrictive for the organization, False if not.

    @param condition_statement: dict with an IAM Condition block, e.g.:
        {
            "StringLike": {
                "AWS:PrincipalOrgID": "o-111122223333"
            }
        }

    """
    is_condition_valid = False

    # The conditions must be defined in lowercase since the context key names are not case-sensitive.
    # For example, including the aws:PrincipalOrgID context key is equivalent to testing for AWS:PrincipalOrgID
    # https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition.html
    valid_condition_options = {
        "StringEquals": [
            "aws:principalorgid",
        ],
        "StringLike": [
            "aws:principalorgid",
        ],
    }

    for condition_operator, condition_operator_key in valid_condition_options.items():
        if condition_operator in condition_statement:
            for value in condition_operator_key:
                # We need to transform the condition_statement into lowercase
                condition_statement[condition_operator] = {
                    k.lower(): v
                    for k, v in condition_statement[condition_operator].items()
                }

                if value in condition_statement[condition_operator]:
                    # values are a list
                    if isinstance(
                        condition_statement[condition_operator][value],
                        list,
                    ):
                        is_condition_valid = True
                        for item in condition_statement[condition_operator][value]:
                            if item == "*":
                                is_condition_valid = False
                                break

                    # value is a string
                    elif isinstance(
                        condition_statement[condition_operator][value],
                        str,
                    ):
                        if "*" not in condition_statement[condition_operator][value]:
                            is_condition_valid = True

    return is_condition_valid


def is_condition_block_restrictive_sns_endpoint(
    condition_statement: dict,
):
    """
    is_condition_block_restrictive_sns_endpoint parses the IAM Condition policy block and returns True if the condition_statement is restrictive for an endpoint, False if not.

    @param condition_statement: dict with an IAM Condition block, e.g.:
        {
            "StringLike": {
                "SNS:Endpoint": "https://events.pagerduty.com/integration/<api-key>/enqueue"
            }
        }

    """
    is_condition_valid = False

    # The conditions must be defined in lowercase since the context key names are not case-sensitive.
    # For example, including the aws:PrincipalOrgID context key is equivalent to testing for AWS:PrincipalOrgID
    # https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition.html
    valid_condition_options = {
        "StringEquals": [
            "sns:endpoint",
        ],
        "StringLike": [
            "sns:endpoint",
        ],
    }

    for condition_operator, condition_operator_key in valid_condition_options.items():
        if condition_operator in condition_statement:
            # https://docs.aws.amazon.com/sns/latest/dg/sns-using-identity-based-policies.html#sns-policy-keys
            # sns:endpoint - The URL, email address, or ARN from a Subscribe request or a previously confirmed subscription.
            pattern = re.compile(r".+@[^*]+|^https:\/\/[^*]+|^arn:aws:sns:[^*]+")
            for value in condition_operator_key:
                # We need to transform the condition_statement into lowercase
                condition_statement[condition_operator] = {
                    k.lower(): v
                    for k, v in condition_statement[condition_operator].items()
                }

                if value in condition_statement[condition_operator]:
                    if pattern.fullmatch(
                        condition_statement[condition_operator][value]
                    ):
                        is_condition_valid = True

    return is_condition_valid


def process_actions(effect, actions, target_set):
    """
    process_actions processes the actions in the policy.
    Args:
        effect (str): The effect of the policy.
        actions (str or list): The actions to process.
        target_set (set): The set to store the actions.
    """
    if effect in ["Allow", "Deny"] and actions:
        if isinstance(actions, str):
            target_set.add(actions)
        elif isinstance(actions, list):
            target_set.update(actions)


def check_admin_access(policy: dict) -> bool:
    """
    check_admin_access checks if the policy allows admin access.
    Args:
        policy (dict): The policy to check.
    Returns:
        bool: True if the policy allows admin access, False otherwise.
    """

    if policy:
        allowed_actions = set()
        allowed_not_actions = set()
        denied_actions = set()
        denied_not_actions = set()

        statements = policy.get("Statement", [])
        if not isinstance(statements, list):
            statements = [statements]

        for statement in statements:
            if statement.get("Resource") in [
                "*",
                ["*"],
                ["*/*"],
                "*/*",
                ["*:*"],
                "*:*",
            ] or (
                statement.get("NotResource")
                and statement.get("NotResource") not in ["*", ["*"]]
            ):
                effect = statement.get("Effect")
                actions = statement.get("Action")
                not_actions = statement.get("NotAction")
                if effect == "Allow":
                    process_actions(effect, actions, allowed_actions)
                    process_actions(effect, not_actions, allowed_not_actions)
                elif effect == "Deny":
                    process_actions(effect, actions, denied_actions)
                    process_actions(effect, not_actions, denied_not_actions)

        # If there is only NotAction, it allows the rest of the actions
        if not allowed_actions and allowed_not_actions:
            allowed_actions.add("*")
        # Check for invalid services in allowed NotAction
        if allowed_not_actions:
            invalid_not_actions = check_invalid_not_actions(allowed_not_actions)
            if invalid_not_actions:
                # Since it is an invalid NotAction, it allows all AWS actions
                allowed_actions.add("*")

        if "*" in allowed_actions:
            return True
        return False


def check_invalid_not_actions(not_actions):
    """
    Checks if the actions in NotAction have services that are not part of AWS.
    Args:
        not_actions (str or list): The NotAction to check.
    Returns:
        dict: A dictionary with invalid services and their actions.
    """
    invalid_services = {}

    if isinstance(not_actions, str):
        not_actions = [not_actions]

    for action in not_actions:
        service = action.split(":")[0]
        if not is_valid_aws_service(service):
            if service not in invalid_services:
                invalid_services[service] = []
            invalid_services[service].append(action)

    return invalid_services


def is_valid_aws_service(service):
    """
    Checks if a service is a valid AWS service using aws_regions_by_service.json.
    Args:
        service (str): The service to check.
    Returns:
        bool: True if the service is valid, False otherwise.
    """
    if service in read_aws_regions_file()["services"]:
        return True
    return False


def is_codebuild_using_allowed_github_org(
    trust_policy: dict, github_repo_url: str, allowed_organizations: list
) -> Tuple[bool, Optional[str]]:
    """
    Checks if the trust policy allows codebuild.amazonaws.com as a trusted principal and if the GitHub organization
    in the repo URL is in the allowed organizations list.
    Returns (is_allowed: bool, org_name: str or None)
    """
    try:
        if not trust_policy or not github_repo_url:
            return False, None

        if not has_codebuild_trusted_principal(trust_policy):
            return False, None

        # Extract org name from GitHub repo URL
        org_name = (
            github_repo_url.split("/")[3]
            if len(github_repo_url.split("/")) > 3
            else None
        )
        if not org_name:
            raise ValueError(f"Malformed GitHub repo URL: {github_repo_url}")
        if org_name in allowed_organizations:
            return True, org_name
        return False, org_name
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        return False, None


def has_codebuild_trusted_principal(trust_policy: dict) -> bool:
    """
    Returns True if the trust policy allows codebuild.amazonaws.com as a trusted principal, otherwise False.
    """
    if not trust_policy:
        return False
    statements = trust_policy.get("Statement", [])
    if not isinstance(statements, list):
        statements = [statements]
    return any(
        s.get("Effect") == "Allow"
        and "Principal" in s
        and (
            (
                isinstance(s["Principal"], dict)
                and (
                    (
                        isinstance(s["Principal"].get("Service"), str)
                        and s["Principal"].get("Service") == "codebuild.amazonaws.com"
                    )
                    or (
                        isinstance(s["Principal"].get("Service"), list)
                        and "codebuild.amazonaws.com" in s["Principal"].get("Service")
                    )
                )
            )
            or (
                isinstance(s["Principal"], str)
                and s["Principal"] == "codebuild.amazonaws.com"
            )
            or (
                isinstance(s["Principal"], list)
                and "codebuild.amazonaws.com" in s["Principal"]
            )
        )
        for s in statements
    )
