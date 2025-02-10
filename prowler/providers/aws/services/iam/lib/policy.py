from ipaddress import ip_address, ip_network

from prowler.lib.logger import logger
from prowler.providers.aws.aws_provider import read_aws_regions_file


def check_full_service_access(service: str, policy: dict) -> bool:
    """
    check_full_service_access checks if the policy allows full access to a service.
    Args:
        service (str): The service to check.
        policy (dict): The policy to check.
    Returns:
        bool: True if the policy allows full access to the service, False otherwise.
    """

    full_access = False

    if policy:
        policy_statements = policy.get("Statement", [])

        if not isinstance(policy_statements, list):
            policy_statements = [policy["Statement"]]

        for statement in policy_statements:
            if statement.get("Effect", "") == "Allow":
                resources = statement.get("Resource", [])

                if not isinstance(resources, list):
                    resources = [statement.get("Resource", [])]

                if "*" in resources:
                    if "Action" in statement:
                        actions = statement.get("Action", [])

                        if not isinstance(actions, list):
                            actions = [actions]

                        if f"{service}:*" in actions:
                            full_access = True
                            break

                    elif "NotAction" in statement:
                        not_actions = statement.get("NotAction", [])

                        if not isinstance(not_actions, list):
                            not_actions = [not_actions]

                        if f"{service}:*" not in not_actions:
                            full_access = True
                            break

    return full_access


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
    Returns:
        bool: True if the policy allows public access, False otherwise
    """
    is_public = False
    if policy:
        for statement in policy.get("Statement", []):
            # Only check allow statements
            if statement["Effect"] == "Allow":
                principal = statement.get("Principal", "")
                if (
                    "*" in principal
                    or "arn:aws:iam::*:root" in principal
                    or (
                        isinstance(principal, dict)
                        and (
                            "*" in principal.get("AWS", "")
                            or "arn:aws:iam::*:root" in principal.get("AWS", "")
                            or (
                                isinstance(principal.get("AWS"), str)
                                and source_account
                                and not is_cross_account_allowed
                                and source_account not in principal.get("AWS", "")
                            )
                            or (
                                isinstance(principal.get("AWS"), list)
                                and (
                                    "*" in principal["AWS"]
                                    or "arn:aws:iam::*:root" in principal["AWS"]
                                    or (
                                        source_account
                                        and not is_cross_account_allowed
                                        and not any(
                                            source_account in principal_aws
                                            for principal_aws in principal["AWS"]
                                        )
                                    )
                                )
                            )
                            or "*" in principal.get("CanonicalUser", "")
                            or "arn:aws:iam::*:root"
                            in principal.get("CanonicalUser", "")
                            or check_cross_service_confused_deputy
                            and (
                                # Check if function can be invoked by other AWS services if check_cross_service_confused_deputy is True
                                (
                                    ".amazonaws.com" in principal.get("Service", "")
                                    or ".amazon.com" in principal.get("Service", "")
                                    or "*" in principal.get("Service", "")
                                )
                                and (
                                    "secretsmanager.amazonaws.com"
                                    not in principal.get(
                                        "Service", ""
                                    )  # AWS ensures that resources called by SecretsManager are executed in the same AWS account
                                    or "eks.amazonaws.com"
                                    not in principal.get(
                                        "Service", ""
                                    )  # AWS ensures that resources called by EKS are executed in the same AWS account
                                )
                            )
                        )
                    )
                ) and (
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
                                if (
                                    source_account
                                    in condition_statement[condition_operator][value]
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
